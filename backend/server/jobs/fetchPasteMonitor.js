// ============================================================
// jobs/fetchPasteMonitor.js — PASTE MONITORING CRON JOB
// ============================================================
// Runs every 5 minutes to scrape Pastebin for IOC matches
// Emits Socket.io events for real-time alerts
// ============================================================

const cron = require('node-cron');
const axios = require('axios');
const IOC = require('../models/IOC');
const PasteHit = require('../models/PasteHit');
const WatchlistPattern = require('../models/WatchlistPattern');
const logger = require('../utils/logger');

// IOC pattern regexes
const IOC_PATTERNS = {
  ip: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g,
  hash: /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g
};

// Sensitive pattern regexes
const SENSITIVE_PATTERNS = {
  credentials: /\b[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]{8,}\b/g,
  cryptoWallet: /\b0x[a-fA-F0-9]{40}\b|\b[13][a-km-zA-Z1-9]{25,34}\b/g,
  cve: /\bCVE-\d{4}-\d{4,}\b/gi,
  emailDump: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g
};

// Exponential backoff retry
const retryWithBackoff = async (fn, maxRetries = 3, baseDelay = 1000) => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i === maxRetries - 1) throw err;
      const delay = baseDelay * Math.pow(2, i);
      logger.warn(`Retry ${i + 1}/${maxRetries} after ${delay}ms: ${err.message}`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
};

// Get all IOCs from DB for pattern matching
const getAllIOCPatterns = async () => {
  try {
    const iocs = await IOC.find({ isActive: true }).lean();
    return iocs;
  } catch (err) {
    logger.error(`Error fetching IOCs: ${err.message}`);
    return [];
  }
};

// Get all active watchlist patterns
const getActiveWatchlistPatterns = async () => {
  try {
    const patterns = await WatchlistPattern.find({ active: true }).lean();
    return patterns;
  } catch (err) {
    logger.error(`Error fetching watchlist patterns: ${err.message}`);
    return [];
  }
};

// Scan text for IOC matches
const scanForIOCs = (text, iocs) => {
  const matches = [];
  
  for (const ioc of iocs) {
    if (text.includes(ioc.indicator)) {
      matches.push({
        type: 'ioc-match',
        value: ioc.indicator,
        iocId: ioc._id,
        severity: ioc.severity
      });
    }
  }
  
  return matches;
};

// Scan text for sensitive patterns
const scanForSensitivePatterns = (text) => {
  const matches = [];
  
  // Check for credentials (user:pass pattern)
  const credentialMatches = text.match(SENSITIVE_PATTERNS.credentials);
  if (credentialMatches) {
    credentialMatches.forEach(match => {
      matches.push({
        type: 'credential',
        value: match,
        severity: 'Critical'
      });
    });
  }
  
  // Check for crypto wallets
  const cryptoMatches = text.match(SENSITIVE_PATTERNS.cryptoWallet);
  if (cryptoMatches) {
    cryptoMatches.forEach(match => {
      matches.push({
        type: 'crypto-wallet',
        value: match,
        severity: 'High'
      });
    });
  }
  
  // Check for CVE references
  const cveMatches = text.match(SENSITIVE_PATTERNS.cve);
  if (cveMatches) {
    cveMatches.forEach(match => {
      matches.push({
        type: 'cve-reference',
        value: match,
        severity: 'Medium'
      });
    });
  }
  
  // Check for email dumps (multiple emails in text)
  const emailMatches = text.match(SENSITIVE_PATTERNS.emailDump);
  if (emailMatches && emailMatches.length > 5) {
    matches.push({
      type: 'email-dump',
      value: `${emailMatches.length} emails found`,
      severity: 'High'
    });
  }
  
  return matches;
};

// Scan text for watchlist patterns
const scanForWatchlistPatterns = (text, patterns) => {
  const matches = [];
  
  for (const pattern of patterns) {
    try {
      let isMatch = false;
      
      if (pattern.patternType === 'regex') {
        const regex = new RegExp(pattern.pattern, 'gi');
        isMatch = regex.test(text);
      } else {
        isMatch = text.toLowerCase().includes(pattern.pattern.toLowerCase());
      }
      
      if (isMatch) {
        matches.push({
          type: 'keyword-match',
          value: pattern.pattern,
          patternId: pattern._id,
          severity: 'Medium'
        });
      }
    } catch (err) {
      logger.error(`Error testing pattern ${pattern.pattern}: ${err.message}`);
    }
  }
  
  return matches;
};

// Determine severity based on match type
const getSeverity = (match) => {
  if (match.severity) return match.severity;
  
  switch (match.type) {
    case 'credential':
      return 'Critical';
    case 'ioc-match':
      return match.severity || 'High';
    case 'crypto-wallet':
    case 'email-dump':
      return 'High';
    case 'cve-reference':
    case 'keyword-match':
      return 'Medium';
    default:
      return 'Low';
  }
};

// Save paste hit to database
const savePasteHit = async (hitData, io) => {
  try {
    const pasteHit = new PasteHit(hitData);
    await pasteHit.save();
    
    // Update pattern hit count if applicable
    if (hitData.patternId) {
      await WatchlistPattern.findByIdAndUpdate(
        hitData.patternId,
        {
          $inc: { hitCount: 1 },
          $set: { lastHit: new Date() }
        }
      );
    }
    
    return pasteHit;
  } catch (err) {
    logger.error(`Error saving paste hit: ${err.message}`);
    return null;
  }
};

// Main paste monitoring function
const monitorPastes = async (io) => {
  try {
    logger.info('Starting paste monitoring cycle...');
    
    // Fetch recent pastes from Pastebin API
    const response = await retryWithBackoff(async () => {
      return await axios.get('https://scrape.pastebin.com/api_scraping.php?limit=50', {
        timeout: 10000
      });
    });
    
    const pastes = response.data;
    if (!pastes || pastes.length === 0) {
      logger.info('No pastes found in this cycle');
      return;
    }
    
    logger.info(`Found ${pastes.length} pastes to analyze`);
    
    // Get IOCs and watchlist patterns
    const iocs = await getAllIOCPatterns();
    const patterns = await getActiveWatchlistPatterns();
    
    let totalMatches = 0;
    
    // Process each paste
    for (const paste of pastes) {
      try {
        // Check if paste already exists
        const existingHit = await PasteHit.findOne({ pasteKey: paste.key });
        if (existingHit) {
          continue; // Skip already processed pastes
        }
        
        // Fetch raw content
        const contentResponse = await retryWithBackoff(async () => {
          return await axios.get(`https://scrape.pastebin.com/api_scrape_item.php?i=${paste.key}`, {
            timeout: 15000
          });
        });
        
        const rawContent = contentResponse.data;
        if (!rawContent) continue;
        
        // Create snippet (first 200 chars)
        const snippet = rawContent.substring(0, 200);
        
        // Scan for matches
        const iocMatches = scanForIOCs(rawContent, iocs);
        const sensitiveMatches = scanForSensitivePatterns(rawContent);
        const watchlistMatches = scanForWatchlistPatterns(rawContent, patterns);
        
        const allMatches = [...iocMatches, ...sensitiveMatches, ...watchlistMatches];
        
        if (allMatches.length === 0) {
          continue; // No matches found
        }
        
        // Save each match as a separate hit
        for (const match of allMatches) {
          const hitData = {
            pasteKey: paste.key,
            pasteUrl: `https://pastebin.com/${paste.key}`,
            pasteTitle: paste.title || 'Untitled',
            matchType: match.type,
            matchedValue: match.value,
            rawSnippet: snippet,
            severity: getSeverity(match),
            source: 'pastebin',
            dateFound: new Date(),
            tags: ['dark-web', 'paste-monitoring', match.type]
          };
          
          if (match.iocId) {
            hitData.iocId = match.iocId;
          }
          
          if (match.patternId) {
            hitData.patternId = match.patternId;
          }
          
          const savedHit = await savePasteHit(hitData, io);
          if (savedHit) {
            totalMatches++;
            
            // Emit Socket.io event for real-time alert
            if (io) {
              io.emit('paste-alert', {
                ioc: savedHit,
                pasteUrl: savedHit.pasteUrl,
                pasteTitle: savedHit.pasteTitle,
                matchType: savedHit.matchType
              });
            }
          }
        }
        
        // Rate limiting: small delay between paste fetches
        await new Promise(resolve => setTimeout(resolve, 500));
        
      } catch (err) {
        logger.error(`Error processing paste ${paste.key}: ${err.message}`);
      }
    }
    
    logger.info(`Paste monitoring cycle completed. Found ${totalMatches} new matches.`);
    
  } catch (err) {
    logger.error(`Error in paste monitoring cycle: ${err.message}`);
  }
};

// Initialize and start the cron job
let ioInstance = null;

const startPasteMonitor = (io) => {
  ioInstance = io;
  
  // Run every 5 minutes
  cron.schedule('*/5 * * * *', async () => {
    await monitorPastes(ioInstance);
  });
  
  logger.info('Paste monitor cron job started (runs every 5 minutes)');
};

module.exports = { startPasteMonitor, monitorPastes };
