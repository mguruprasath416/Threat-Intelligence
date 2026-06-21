// ============================================================
// controllers/iocController.js — IOC BUSINESS LOGIC
// ============================================================
// Controllers are the bridge between routes and services.
// They handle:
//   - Extracting data from req (body, params, query)
//   - Calling the right service functions
//   - Saving/retrieving from MongoDB
//   - Sending the HTTP response
//
// They do NOT: contain business logic (that's in services)
// They do NOT: talk to external APIs directly (that's in services)
//
// Endpoints handled:
//   POST /api/ioc/search       → Search/enrich a single IOC
//   GET  /api/ioc              → List all IOCs (paginated)
//   GET  /api/ioc/:id          → Get one IOC by ID
//   GET  /api/ioc/stats        → Dashboard stats
//   DELETE /api/ioc/:id        → Delete an IOC (admin only)
//   PATCH /api/ioc/:id/flag    → Flag as false positive
// ============================================================

const IOC              = require('../models/IOC');
const ThreatActor      = require('../models/ThreatActor');
const { enrichIOC }    = require('../services/enrichmentService');
const { validateIOC }  = require('../utils/iocValidator');
const logger           = require('../utils/logger');
const csv              = require('csv-parser');
const fs               = require('fs');
const { Readable }     = require('stream');

// ── POST /api/ioc/search ──────────────────────────────────
// Main endpoint — takes an indicator, enriches it, saves to DB
// If it already exists in DB and is recent, returns cached version
const searchIOC = async (req, res, next) => {
  try {
    const { indicator } = req.body;

    if (!indicator) {
      return res.status(400).json({ success: false, message: 'indicator is required' });
    }

    // Step 1: Validate the indicator format
    const validation = validateIOC(indicator.trim());
    if (!validation.valid) {
      return res.status(400).json({ success: false, message: validation.error });
    }

    // Step 2: Check if we already have fresh data in DB for THIS user
    // "Fresh" = enriched within the last 24 hours
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const userId    = req.user.userId;

    let existingIOC = await IOC.findOne({
      indicator:   indicator.trim(),
      iocType:     validation.type,
      submittedBy: userId,
    });

    if (existingIOC && existingIOC.lastEnriched > oneDayAgo) {
      logger.info(`Cache hit for ${indicator} (User: ${userId}) — returning stored data`);
      return res.status(200).json({
        success: true,
        cached:  true,
        data:    existingIOC,
      });
    }

    // Step 3: Enrich — call all relevant APIs
    logger.info(`Cache miss for ${indicator} (User: ${userId}) — enriching now`);
    const enrichedData = await enrichIOC(indicator.trim());

    // Step 4: Save or update in MongoDB (scoped to user)
    const savedIOC = await IOC.findOneAndUpdate(
      { 
        indicator:   indicator.trim(), 
        iocType:     validation.type,
        submittedBy: userId 
      },
      {
        $set: {
          ...enrichedData,
          submittedBy: userId,
        }
      },
      {
        new:    true,
        upsert: true,
        runValidators: true,
      }
    );

    res.status(200).json({
      success: true,
      cached:  false,
      data:    savedIOC,
    });

  } catch (err) {
    logger.error(`searchIOC error: ${err.message}`);
    next(err); // Pass to global error handler
  }
};

// ── GET /api/ioc ──────────────────────────────────────────
// List all IOCs with filtering, sorting, pagination
const getAllIOCs = async (req, res, next) => {
  try {
    const {
      page     = 1,
      limit    = 20,
      severity,        // Filter by severity: Low|Medium|High|Critical
      iocType,         // Filter by type: ip|domain|url|hash
      search,          // Text search on indicator field
      sortBy   = 'createdAt',
      sortOrder = 'desc',
      isActive = true,
    } = req.query;

    // Build MongoDB query filter dynamically — scope to user
    const filter = { 
      isActive: isActive === 'true' || isActive === true,
      submittedBy: req.user.userId 
    };

    if (severity) filter.severity = severity;
    if (iocType)  filter.iocType  = iocType;

    // Text search on indicator field
    if (search) {
      filter.indicator = { $regex: search, $options: 'i' }; // case-insensitive
    }

    // Sort direction: 'desc' → -1, 'asc' → 1
    const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

    // Pagination math
    const skip  = (parseInt(page) - 1) * parseInt(limit);
    const total = await IOC.countDocuments(filter);

    const iocs = await IOC.find(filter)
      .sort(sort)
      .skip(skip)
      .limit(parseInt(limit))
      .populate('submittedBy', 'username email') // Join user data
      .lean(); // .lean() returns plain JS objects, faster than Mongoose docs

    res.status(200).json({
      success: true,
      data: {
        iocs,
        pagination: {
          total,
          page:       parseInt(page),
          limit:      parseInt(limit),
          totalPages: Math.ceil(total / parseInt(limit)),
        },
      },
    });

  } catch (err) {
    logger.error(`getAllIOCs error: ${err.message}`);
    next(err);
  }
};

// ── GET /api/ioc/stats ────────────────────────────────────
// Aggregated statistics for the dashboard charts
const getIOCStats = async (req, res, next) => {
  try {

    const userId = req.user.userId;
    const commonMatch = { isActive: true, submittedBy: userId };

    // Run all aggregations in parallel for speed
    const [
      severityCounts,
      typeCounts,
      topCountries,
      recentTrend,
      topTags,
    ] = await Promise.all([

      // Count by severity level
      IOC.aggregate([
        { $match: commonMatch },
        { $group: { _id: '$severity', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),

      // Count by IOC type
      IOC.aggregate([
        { $match: commonMatch },
        { $group: { _id: '$iocType', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),

      // Top countries by IP IOCs
      IOC.aggregate([
        { 
          $match: { 
            ...commonMatch, 
            iocType: 'ip', 
            'geoLocation.country': { $ne: null } 
          } 
        },
        { $group: { _id: '$geoLocation.country', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),

      // IOCs per day for the last 30 days (for trend chart)
      IOC.aggregate([
        {
          $match: {
            ...commonMatch,
            createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
          }
        },
        {
          $group: {
            _id: {
              $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
            },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } },
      ]),

      // Top tags
      IOC.aggregate([
        { $match: commonMatch },
        { $unwind: '$tags' },
        { $group: { _id: '$tags', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 15 },
      ]),
    ]);

    // Total count
    const totalIOCs = await IOC.countDocuments(commonMatch);

    res.status(200).json({
      success: true,
      data: {
        totalIOCs,
        severityDistribution: severityCounts,
        typeDistribution:     typeCounts,
        topCountries,
        dailyTrend:           recentTrend,
        topTags,
      },
    });

  } catch (err) {
    logger.error(`getIOCStats error: ${err.message}`);
    next(err);
  }
};

// ── GET /api/ioc/:id ──────────────────────────────────────
// Get a single IOC with full enrichment details
const getIOCById = async (req, res, next) => {
  try {
    const ioc = await IOC.findOne({ _id: req.params.id, submittedBy: req.user.userId })
      .populate('submittedBy', 'username email');

    if (!ioc) {
      return res.status(404).json({ success: false, message: 'IOC not found or access denied' });
    }

    res.status(200).json({ success: true, data: ioc });

  } catch (err) {
    logger.error(`getIOCById error: ${err.message}`);
    next(err);
  }
};

// ── DELETE /api/ioc/:id ───────────────────────────────────
// Soft delete — sets isActive to false (data preserved)
// Only admin role can delete
const deleteIOC = async (req, res, next) => {
  try {
    const ioc = await IOC.findOneAndUpdate(
      { _id: req.params.id, submittedBy: req.user.userId },
      { $set: { isActive: false } },
      { new: true }
    );

    if (!ioc) {
      return res.status(404).json({ success: false, message: 'IOC not found or access denied' });
    }

    logger.info(`IOC ${req.params.id} soft-deleted by ${req.user.username}`);
    res.status(200).json({ success: true, message: 'IOC archived successfully' });

  } catch (err) {
    logger.error(`deleteIOC error: ${err.message}`);
    next(err);
  }
};

// ── PATCH /api/ioc/:id/flag ───────────────────────────────
// Toggle false positive flag on an IOC
const flagFalsePositive = async (req, res, next) => {
  try {
    const ioc = await IOC.findOne({ _id: req.params.id, submittedBy: req.user.userId });
    if (!ioc) {
      return res.status(404).json({ success: false, message: 'IOC not found or access denied' });
    }

    ioc.isFP = !ioc.isFP; // Toggle
    await ioc.save();

    logger.info(`IOC ${req.params.id} FP flag toggled to ${ioc.isFP} by ${req.user.username}`);

    res.status(200).json({
      success: true,
      message: `IOC marked as ${ioc.isFP ? 'false positive' : 'true positive'}`,
      data:    ioc,
    });

  } catch (err) {
    logger.error(`flagFalsePositive error: ${err.message}`);
    next(err);
  }
};

// ── GET /api/ioc/mitre/coverage ───────────────────────────
// Aggregates counts of active mapped MITRE techniques
const getMitreCoverage = async (req, res, next) => {
  try {
    const userId = req.user.userId;

    const coverage = await IOC.aggregate([
      // 1. Only count active IOCs owned by the user
      { $match: { isActive: true, submittedBy: userId } },
      // 2. Unwind the mitreTechniques subdocument array
      { $unwind: '$mitreTechniques' },
      // 3. Group by technique ID and sum occurrences
      {
        $group: {
          _id: '$mitreTechniques.techniqueId',
          techniqueId:   { $first: '$mitreTechniques.techniqueId' },
          techniqueName: { $first: '$mitreTechniques.techniqueName' },
          tactic:        { $first: '$mitreTechniques.tactic' },
          killChainStage:{ $first: '$mitreTechniques.killChainStage' },
          count:         { $sum: 1 },
        }
      },
      // 4. Sort by count descending
      { $sort: { count: -1 } }
    ]);

    res.status(200).json({
      success: true,
      data: coverage
    });
  } catch (err) {
    logger.error(`getMitreCoverage error: ${err.message}`);
    next(err);
  }
};


// ── PATCH /api/ioc/:id/mitre ──────────────────────────────
// Update the MITRE ATT&CK technique mappings for an IOC
const updateMitreTechniques = async (req, res, next) => {
  try {
    const { mitreTechniques } = req.body;

    if (!Array.isArray(mitreTechniques)) {
      return res.status(400).json({
        success: false,
        message: 'mitreTechniques must be an array',
      });
    }

    const ioc = await IOC.findOneAndUpdate(
      { _id: req.params.id, submittedBy: req.user.userId },
      { $set: { mitreTechniques } },
      { new: true, runValidators: true }
    );

    if (!ioc) {
      return res.status(404).json({
        success: false,
        message: 'IOC not found or not owned by you',
      });
    }

    logger.info(`MITRE techniques updated for IOC ${ioc._id} by ${req.user.username}`);
    res.status(200).json({ success: true, data: ioc });
  } catch (err) {
    next(err);
  }
};

// ── GET /api/ioc/graph/:id ───────────────────────────────────
// Returns nodes and edges for relationship graph visualization
// Traverses related IOCs through tags, threat actors, and similar indicators
const getGraphData = async (req, res, next) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    const maxDepth = 2; // How many levels deep to traverse
    const maxNodes = 50; // Limit total nodes to prevent performance issues

    // Get the starting IOC
    const startIOC = await IOC.findOne({ _id: id, submittedBy: userId });
    if (!startIOC) {
      return res.status(404).json({ success: false, message: 'IOC not found' });
    }

    const nodes = new Map();
    const edges = [];
    const visited = new Set();
    const queue = [{ ioc: startIOC, depth: 0 }];

    // Add starting node
    nodes.set(startIOC._id.toString(), {
      id: startIOC._id.toString(),
      label: startIOC.indicator,
      type: 'ioc',
      iocType: startIOC.iocType,
      severity: startIOC.severity,
      threatScore: startIOC.threatScore,
      data: startIOC
    });
    visited.add(startIOC._id.toString());

    // BFS traversal to find related IOCs
    while (queue.length > 0 && nodes.size < maxNodes) {
      const { ioc, depth } = queue.shift();

      if (depth >= maxDepth) continue;

      // Find IOCs with same tags
      if (ioc.tags && ioc.tags.length > 0) {
        const relatedByTags = await IOC.find({
          _id: { $ne: ioc._id },
          submittedBy: userId,
          isActive: true,
          tags: { $in: ioc.tags }
        }).limit(10);

        for (const related of relatedByTags) {
          const relatedId = related._id.toString();
          if (!visited.has(relatedId) && nodes.size < maxNodes) {
            visited.add(relatedId);
            nodes.set(relatedId, {
              id: relatedId,
              label: related.indicator,
              type: 'ioc',
              iocType: related.iocType,
              severity: related.severity,
              threatScore: related.threatScore,
              data: related
            });
            queue.push({ ioc: related, depth: depth + 1 });
          }
          if (visited.has(relatedId)) {
            edges.push({
              source: ioc._id.toString(),
              target: relatedId,
              label: 'shared tag',
              type: 'tag'
            });
          }
        }
      }

      // Find IOCs with same MITRE techniques
      if (ioc.mitreTechniques && ioc.mitreTechniques.length > 0) {
        const techniqueIds = ioc.mitreTechniques.map(t => t.techniqueId);
        const relatedByMitre = await IOC.find({
          _id: { $ne: ioc._id },
          submittedBy: userId,
          isActive: true,
          'mitreTechniques.techniqueId': { $in: techniqueIds }
        }).limit(10);

        for (const related of relatedByMitre) {
          const relatedId = related._id.toString();
          if (!visited.has(relatedId) && nodes.size < maxNodes) {
            visited.add(relatedId);
            nodes.set(relatedId, {
              id: relatedId,
              label: related.indicator,
              type: 'ioc',
              iocType: related.iocType,
              severity: related.severity,
              threatScore: related.threatScore,
              data: related
            });
            queue.push({ ioc: related, depth: depth + 1 });
          }
          if (visited.has(relatedId)) {
            edges.push({
              source: ioc._id.toString(),
              target: relatedId,
              label: 'MITRE technique',
              type: 'mitre'
            });
          }
        }
      }

      // Find threat actors linked to this IOC
      const threatActors = await ThreatActor.find({
        linkedIOCs: ioc._id,
        isActive: true
      }).populate('linkedIOCs', 'indicator iocType severity threatScore');

      for (const actor of threatActors) {
        const actorId = actor._id.toString();
        if (!visited.has(actorId) && nodes.size < maxNodes) {
          visited.add(actorId);
          nodes.set(actorId, {
            id: actorId,
            label: actor.name,
            type: 'threat_actor',
            data: actor
          });
        }

        // Add edge from IOC to threat actor
        edges.push({
          source: ioc._id.toString(),
          target: actorId,
          label: 'attributed to',
          type: 'attribution'
        });

        // Add edges from threat actor to other linked IOCs
        for (const linkedIOC of actor.linkedIOCs || []) {
          const linkedId = linkedIOC._id.toString();
          if (linkedId !== ioc._id.toString()) {
            if (!visited.has(linkedId) && nodes.size < maxNodes) {
              visited.add(linkedId);
              nodes.set(linkedId, {
                id: linkedId,
                label: linkedIOC.indicator,
                type: 'ioc',
                iocType: linkedIOC.iocType,
                severity: linkedIOC.severity,
                threatScore: linkedIOC.threatScore,
                data: linkedIOC
              });
              queue.push({ ioc: linkedIOC, depth: depth + 1 });
            }
            if (visited.has(linkedId)) {
              edges.push({
                source: actorId,
                target: linkedId,
                label: 'uses',
                type: 'attribution'
              });
            }
          }
        }
      }

      // Find IOCs with similar indicators (same domain for IPs, same IP for domains)
      if (ioc.iocType === 'domain') {
        // Find IPs that resolve to this domain (simplified - in real app, use DNS data)
        const relatedByDomain = await IOC.find({
          _id: { $ne: ioc._id },
          submittedBy: userId,
          isActive: true,
          iocType: 'ip',
          indicator: { $regex: ioc.indicator, $options: 'i' }
        }).limit(5);

        for (const related of relatedByDomain) {
          const relatedId = related._id.toString();
          if (!visited.has(relatedId) && nodes.size < maxNodes) {
            visited.add(relatedId);
            nodes.set(relatedId, {
              id: relatedId,
              label: related.indicator,
              type: 'ioc',
              iocType: related.iocType,
              severity: related.severity,
              threatScore: related.threatScore,
              data: related
            });
            queue.push({ ioc: related, depth: depth + 1 });
          }
          if (visited.has(relatedId)) {
            edges.push({
              source: ioc._id.toString(),
              target: relatedId,
              label: 'related indicator',
              type: 'indicator'
            });
          }
        }
      }
    }

    // Add campaign nodes from threat actors
    for (const [nodeId, node] of nodes) {
      if (node.type === 'threat_actor' && node.data.campaigns) {
        for (const campaign of node.data.campaigns) {
          const campaignId = `campaign-${nodeId}-${campaign.name}`;
          if (!visited.has(campaignId) && nodes.size < maxNodes) {
            visited.add(campaignId);
            nodes.set(campaignId, {
              id: campaignId,
              label: campaign.name,
              type: 'campaign',
              data: campaign
            });
            edges.push({
              source: nodeId,
              target: campaignId,
              label: 'campaign',
              type: 'campaign'
            });
          }
        }
      }
    }

    res.status(200).json({
      success: true,
      data: {
        nodes: Array.from(nodes.values()),
        edges: edges
      }
    });

  } catch (err) {
    logger.error(`getGraphData error: ${err.message}`);
    next(err);
  }
};

// ── POST /api/ioc/bulk-import ───────────────────────────────
// Bulk import IOCs from CSV or JSON file upload
// Validates each row with iocValidator.js and returns a report
const bulkImportIOCs = async (req, res, next) => {
  try {
    const userId = req.user.userId;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }

    const results = {
      total: 0,
      successful: 0,
      failed: 0,
      skipped: 0,
      errors: []
    };

    let iocsToInsert = [];

    // Parse CSV file
    if (file.mimetype === 'text/csv' || file.originalname.endsWith('.csv')) {
      const stream = fs.createReadStream(file.path);
      
      await new Promise((resolve, reject) => {
        stream
          .pipe(csv())
          .on('data', (row) => {
            results.total++;
            const indicator = row.indicator || row.Indicator || row.INDICATOR;
            const tags = row.tags || row.Tags || row.TAGS || '';
            const severity = row.severity || row.Severity || row.SEVERITY || 'Low';

            if (!indicator) {
              results.failed++;
              results.errors.push({
                row: results.total,
                indicator: 'N/A',
                error: 'Missing indicator field'
              });
              return;
            }

            // Validate IOC
            const validation = validateIOC(indicator.trim());
            if (!validation.valid) {
              results.failed++;
              results.errors.push({
                row: results.total,
                indicator: indicator.trim(),
                error: validation.error
              });
              return;
            }

            // Check if IOC already exists for this user
            IOC.findOne({
              indicator: indicator.trim(),
              iocType: validation.type,
              submittedBy: userId
            }).then(existing => {
              if (existing) {
                results.skipped++;
              } else {
                iocsToInsert.push({
                  indicator: indicator.trim(),
                  iocType: validation.type,
                  severity: severity || 'Low',
                  tags: tags ? tags.split(',').map(t => t.trim()) : [],
                  source: 'bulk-import',
                  submittedBy: userId,
                  isActive: true,
                  isFP: false
                });
              }
            }).catch(err => {
              results.failed++;
              results.errors.push({
                row: results.total,
                indicator: indicator.trim(),
                error: 'Database check failed'
              });
            });
          })
          .on('end', async () => {
            // Insert valid IOCs
            if (iocsToInsert.length > 0) {
              try {
                const inserted = await IOC.insertMany(iocsToInsert);
                results.successful = inserted.length;
              } catch (err) {
                logger.error(`Bulk insert error: ${err.message}`);
                results.failed += iocsToInsert.length;
                results.errors.push({
                  error: 'Bulk insert failed',
                  details: err.message
                });
              }
            }

            // Clean up uploaded file
            fs.unlinkSync(file.path);
            resolve();
          })
          .on('error', (err) => {
            logger.error(`CSV parsing error: ${err.message}`);
            reject(err);
          });
      });

    } else if (file.mimetype === 'application/json' || file.originalname.endsWith('.json')) {
      // Parse JSON file
      const jsonData = JSON.parse(fs.readFileSync(file.path, 'utf8'));
      const iocsArray = Array.isArray(jsonData) ? jsonData : jsonData.iocs || [];

      results.total = iocsArray.length;

      for (let i = 0; i < iocsArray.length; i++) {
        const item = iocsArray[i];
        const indicator = item.indicator || item.Indicator || item.INDICATOR;
        const tags = item.tags || item.Tags || item.TAGS || '';
        const severity = item.severity || item.Severity || item.SEVERITY || 'Low';

        if (!indicator) {
          results.failed++;
          results.errors.push({
            row: i + 1,
            indicator: 'N/A',
            error: 'Missing indicator field'
          });
          continue;
        }

        // Validate IOC
        const validation = validateIOC(indicator.trim());
        if (!validation.valid) {
          results.failed++;
          results.errors.push({
            row: i + 1,
            indicator: indicator.trim(),
            error: validation.error
          });
          continue;
        }

        // Check if IOC already exists for this user
        const existing = await IOC.findOne({
          indicator: indicator.trim(),
          iocType: validation.type,
          submittedBy: userId
        });

        if (existing) {
          results.skipped++;
        } else {
          iocsToInsert.push({
            indicator: indicator.trim(),
            iocType: validation.type,
            severity: severity || 'Low',
            tags: tags ? (Array.isArray(tags) ? tags : tags.split(',').map(t => t.trim())) : [],
            source: 'bulk-import',
            submittedBy: userId,
            isActive: true,
            isFP: false
          });
        }
      }

      // Insert valid IOCs
      if (iocsToInsert.length > 0) {
        const inserted = await IOC.insertMany(iocsToInsert);
        results.successful = inserted.length;
      }

      // Clean up uploaded file
      fs.unlinkSync(file.path);

    } else {
      fs.unlinkSync(file.path);
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid file format. Please upload CSV or JSON.' 
      });
    }

    logger.info(`Bulk import completed for user ${userId}: ${results.successful} successful, ${results.failed} failed, ${results.skipped} skipped`);

    res.status(200).json({
      success: true,
      message: 'Bulk import completed',
      data: results
    });

  } catch (err) {
    // Clean up file on error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    logger.error(`bulkImportIOCs error: ${err.message}`);
    next(err);
  }
};

// ── GET /api/ioc/export ──────────────────────────────────────
// Export IOCs to CSV with optional filtering
const exportIOCs = async (req, res, next) => {
  try {
    const userId = req.user.userId;
    const {
      severity,
      iocType,
      search,
      isActive = true
    } = req.query;

    // Build filter
    const filter = {
      isActive: isActive === 'true' || isActive === true,
      submittedBy: userId
    };

    if (severity) filter.severity = severity;
    if (iocType) filter.iocType = iocType;
    if (search) filter.indicator = { $regex: search, $options: 'i' };

    // Fetch IOCs
    const iocs = await IOC.find(filter)
      .sort({ createdAt: -1 })
      .lean();

    // Convert to CSV
    const csvHeader = 'indicator,iocType,severity,threatScore,source,tags,createdAt\n';
    const csvRows = iocs.map(ioc => {
      const tags = ioc.tags ? `"${ioc.tags.join(',')}"` : '';
      const createdAt = ioc.createdAt ? new Date(ioc.createdAt).toISOString() : '';
      return `${ioc.indicator},${ioc.iocType},${ioc.severity},${ioc.threatScore},${ioc.source},${tags},${createdAt}`;
    }).join('\n');

    const csvContent = csvHeader + csvRows;

    // Set headers for CSV download
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="ioc-export-${Date.now()}.csv"`);
    
    res.send(csvContent);

    logger.info(`Export completed for user ${userId}: ${iocs.length} IOCs exported`);

  } catch (err) {
    logger.error(`exportIOCs error: ${err.message}`);
    next(err);
  }
};

module.exports = {
  searchIOC,
  getAllIOCs,
  getIOCStats,
  getIOCById,
  deleteIOC,
  flagFalsePositive,
  getMitreCoverage,
  updateMitreTechniques,
  getGraphData,
  bulkImportIOCs,
  exportIOCs,
};
