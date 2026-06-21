// ============================================================
// services/emailService.js — EMAIL / OTP DELIVERY
// ============================================================
// Uses HTTP REST APIs (Brevo / Resend) over HTTPS port 443
// to bypass ISP/cloud outbound SMTP port blocks.
// Falls back to Nodemailer SMTP (Gmail, custom, or Ethereal).
// ============================================================

const axios      = require('axios');
const nodemailer = require('nodemailer');
const logger     = require('../utils/logger');

// ── Nodemailer Transporter cache ──────────────────────────
let transporter;

const getTransporter = async () => {
  if (transporter) return transporter;

  if (process.env.EMAIL_PROVIDER === 'ethereal') {
    // Ethereal: auto-creates a free throwaway account (dev/test)
    try {
      const testAccount = await nodemailer.createTestAccount();
      transporter = nodemailer.createTransport({
        host:   'smtp.ethereal.email',
        port:   587,
        secure: false,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass,
        },
      });
      logger.info(`Ethereal email account: ${testAccount.user}`);
    } catch (err) {
      logger.warn(`Failed to create Ethereal account: ${err.message}. Falling back to console-only mode.`);
      transporter = null;
    }
  } else {
    // Production / real SMTP (Gmail, Outlook, Mailgun, etc.)
    transporter = nodemailer.createTransport({
      host:   process.env.SMTP_HOST,
      port:   parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true', // true for port 465
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }

  return transporter;
};

// ── Send OTP Email ────────────────────────────────────────
const sendOtpEmail = async (email, otp) => {
  // Always log OTP to console for easy development testing
  logger.info(`[AUTH OTP] Code for ${email}: ${otp}`);

  const subject = 'Your IOC Sentinel Access Code';
  const textContent = `Your one-time access code is: ${otp}\n\nThis code expires in 10 minutes.\nDo not share this code with anyone.`;
  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8" />
      <style>
        body { margin:0; padding:0; background:#0a0d14; font-family:'Courier New',monospace; }
        .container { max-width:480px; margin:40px auto; background:#0f1219;
          border:1px solid rgba(0,212,255,0.2); border-radius:12px; overflow:hidden; }
        .header { background:linear-gradient(135deg,#0a1628,#0f1e35);
          padding:32px; text-align:center; border-bottom:1px solid rgba(0,212,255,0.15); }
        .hex-icon { font-size:48px; display:block; margin-bottom:12px; }
        .brand { color:#00d4ff; font-size:20px; font-weight:700; letter-spacing:0.2em; }
        .tagline { color:#4a6080; font-size:11px; letter-spacing:0.12em; margin-top:4px; }
        .body { padding:36px 32px; }
        .greeting { color:#8899aa; font-size:13px; margin-bottom:24px; }
        .otp-label { color:#4a6080; font-size:10px; letter-spacing:0.15em; margin-bottom:12px; }
        .otp-box { background:#0a0d14; border:1px solid rgba(0,212,255,0.3);
          border-radius:8px; padding:20px; text-align:center; margin-bottom:24px;
          box-shadow:0 0 20px rgba(0,212,255,0.06); }
        .otp-code { color:#00d4ff; font-size:40px; font-weight:700; letter-spacing:0.3em;
          text-shadow:0 0 20px rgba(0,212,255,0.5); }
        .expires { color:#4a6080; font-size:11px; margin-top:8px; }
        .warning { background:rgba(255,51,85,0.06); border:1px solid rgba(255,51,85,0.2);
          border-radius:6px; padding:12px 16px; color:#ff3355; font-size:11px;
          letter-spacing:0.04em; margin-bottom:24px; }
        .footer { padding:20px 32px; border-top:1px solid rgba(0,212,255,0.08);
          text-align:center; color:#2a3a4a; font-size:10px; letter-spacing:0.08em; }
        .dot { display:inline-block; width:6px; height:6px; background:#00d4ff;
          border-radius:50%; margin-right:6px; box-shadow:0 0 6px #00d4ff; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <span class="hex-icon">⬡</span>
          <div class="brand">IOC SENTINEL</div>
          <div class="tagline">THREAT INTELLIGENCE PLATFORM</div>
        </div>
        <div class="body">
          <div class="greeting">A sign-in request was made for <strong style="color:#00d4ff">${email}</strong>.<br/>Use the code below to access the platform.</div>
          <div class="otp-label">ONE-TIME ACCESS CODE</div>
          <div class="otp-box">
            <div class="otp-code">${otp}</div>
            <div class="expires">⏱ Expires in 10 minutes</div>
          </div>
          <div class="warning">⚠ Do not share this code. IOC Sentinel will never ask for it via phone or chat.</div>
        </div>
        <div class="footer">
          <span class="dot"></span>SYSTEM ONLINE — AUTHORIZED ACCESS ONLY
        </div>
      </div>
    </body>
    </html>
  `;

  // ── Option A: Brevo HTTP REST API (HTTPS port 443 — bypasses SMTP blocks) ──
  if (process.env.BREVO_API_KEY) {
    try {
      const senderEmail = process.env.BREVO_SENDER_EMAIL || process.env.SMTP_USER || 'noreply@iocsentinel.io';
      await axios.post('https://api.brevo.com/v3/smtp/email', {
        sender: { name: 'IOC Sentinel Security', email: senderEmail },
        to: [{ email }],
        subject,
        htmlContent
      }, {
        headers: {
          'accept': 'application/json',
          'api-key': process.env.BREVO_API_KEY,
          'content-type': 'application/json'
        }
      });
      logger.info(`OTP sent via Brevo HTTP API to ${email}`);
      return { success: true, provider: 'brevo' };
    } catch (err) {
      logger.error(`Brevo API error: ${err.response?.data?.message || err.message}`);
      // Fallback allowed in development, throws in production
      if (process.env.NODE_ENV !== 'development') throw err;
    }
  }

  // ── Option B: Resend HTTP REST API (HTTPS port 443 — bypasses SMTP blocks) ──
  if (process.env.RESEND_API_KEY) {
    try {
      const fromEmail = process.env.RESEND_SENDER_EMAIL || 'onboarding@resend.dev';
      await axios.post('https://api.resend.com/emails', {
        from: `IOC Sentinel Security <${fromEmail}>`,
        to: email,
        subject,
        html: htmlContent
      }, {
        headers: {
          'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
          'Content-Type': 'application/json'
        }
      });
      logger.info(`OTP sent via Resend HTTP API to ${email}`);
      return { success: true, provider: 'resend' };
    } catch (err) {
      logger.error(`Resend API error: ${err.response?.data?.message || err.message}`);
      // Fallback allowed in development, throws in production
      if (process.env.NODE_ENV !== 'development') throw err;
    }
  }

  // ── Option C: Nodemailer SMTP (Gmail / Custom / Ethereal) ─────────────────
  try {
    const transport = await getTransporter();
    if (!transport) {
      logger.warn(`No email transporter available. OTP was logged to console.`);
      return { success: false, mode: 'console-fallback' };
    }

    const mailOptions = {
      from: `"IOC Sentinel 🛡️" <${process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@iocsentinel.io'}>`,
      to:   email,
      subject,
      text: textContent,
      html: htmlContent,
    };

    const info = await transport.sendMail(mailOptions);

    if (process.env.EMAIL_PROVIDER === 'ethereal') {
      const previewUrl = nodemailer.getTestMessageUrl(info);
      logger.info(`OTP email preview: ${previewUrl}`);
    }

    return info;
  } catch (err) {
    logger.error(`Error sending OTP email via SMTP: ${err.message}`);
    // If in development mode, we succeed anyway and print a warning
    if (process.env.NODE_ENV === 'development') {
      logger.info(`[DEV] Continuing auth flow since NODE_ENV is development.`);
      return { success: false, mode: 'console-fallback-error' };
    }
    // In production, we throw the error
    throw err;
  }
};

const sendAlertEmail = async (email, alertData) => {
  logger.info(`[WATCHLIST ALERT EMAIL] Sending alert to ${email}: matched pattern "${alertData.matchedPattern}" on indicator "${alertData.iocIndicator}"`);

  const subject = `🛡️ Security Alert: Watchlist Match Found!`;
  const textContent = `A new threat indicator matching your watchlist pattern was detected.\n\n` +
    `Indicator: ${alertData.iocIndicator}\n` +
    `Type: ${alertData.iocType.toUpperCase()}\n` +
    `Severity: ${alertData.severity}\n` +
    `Matched Keyword/Pattern: ${alertData.matchedPattern}\n\n` +
    `Please log in to the IOC Sentinel dashboard to review this alert.`;

  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8" />
      <style>
        body { margin:0; padding:0; background:#0a0d14; font-family:'Courier New',monospace; }
        .container { max-width:550px; margin:40px auto; background:#0f1219;
          border:1px solid rgba(255,59,92,0.2); border-radius:12px; overflow:hidden; }
        .header { background:linear-gradient(135deg,#1b0d14,#290f19);
          padding:32px; text-align:center; border-bottom:1px solid rgba(255,59,92,0.25); }
        .hex-icon { font-size:48px; display:block; margin-bottom:12px; color:#ff3b5c; }
        .brand { color:#ff3b5c; font-size:20px; font-weight:700; letter-spacing:0.2em; }
        .tagline { color:#804a5c; font-size:11px; letter-spacing:0.12em; margin-top:4px; }
        .body { padding:36px 32px; }
        .greeting { color:#8899aa; font-size:13px; margin-bottom:24px; }
        .details-label { color:#804a5c; font-size:10px; letter-spacing:0.15em; margin-bottom:12px; }
        .details-box { background:#0a0d14; border:1px solid rgba(255,59,92,0.3);
          border-radius:8px; padding:20px; margin-bottom:24px;
          box-shadow:0 0 20px rgba(255,59,92,0.06); }
        .detail-row { display:flex; margin-bottom:10px; font-size:12px; }
        .detail-row:last-child { margin-bottom:0; }
        .detail-key { color:#8a9bb0; width:140px; font-weight:bold; }
        .detail-val { color:#e8f0fa; word-break:break-all; }
        .detail-val.highlight { color:#ff3b5c; font-weight:bold; }
        .footer { padding:20px 32px; border-top:1px solid rgba(255,59,92,0.08);
          text-align:center; color:#4a2a3a; font-size:10px; letter-spacing:0.08em; }
        .dot { display:inline-block; width:6px; height:6px; background:#ff3b5c;
          border-radius:50%; margin-right:6px; box-shadow:0 0 6px #ff3b5c; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <span class="hex-icon">⚠️</span>
          <div class="brand">WATCHLIST ALERT</div>
          <div class="tagline">THREAT DETECTION SYSTEM</div>
        </div>
        <div class="body">
          <div class="greeting">Hello Security Analyst,<br/><br/>A new indicator has matched one of your watchlist patterns. See the details below:</div>
          <div class="details-label">ALERT IDENTIFICATION REPORT</div>
          <div class="details-box">
            <div class="detail-row">
              <span class="detail-key">Indicator:</span>
              <span class="detail-val highlight">${alertData.iocIndicator}</span>
            </div>
            <div class="detail-row">
              <span class="detail-key">IOC Type:</span>
              <span class="detail-val">${alertData.iocType.toUpperCase()}</span>
            </div>
            <div class="detail-row">
              <span class="detail-key">Severity:</span>
              <span class="detail-val" style="color: ${alertData.severity === 'Critical' ? '#ff3b5c' : '#f5a623'}">${alertData.severity}</span>
            </div>
            <div class="detail-row">
              <span class="detail-key">Matched Pattern:</span>
              <span class="detail-val highlight">${alertData.matchedPattern}</span>
            </div>
          </div>
        </div>
        <div class="footer">
          <span class="dot"></span>SYSTEM ONLINE — AUTHORIZED ACCESS ONLY
        </div>
      </div>
    </body>
    </html>
  `;

  // ── Option A: Brevo HTTP REST API (HTTPS port 443 — bypasses SMTP blocks) ──
  if (process.env.BREVO_API_KEY) {
    try {
      const senderEmail = process.env.BREVO_SENDER_EMAIL || process.env.SMTP_USER || 'noreply@iocsentinel.io';
      await axios.post('https://api.brevo.com/v3/smtp/email', {
        sender: { name: 'IOC Sentinel Alerts', email: senderEmail },
        to: [{ email }],
        subject,
        htmlContent
      }, {
        headers: {
          'accept': 'application/json',
          'api-key': process.env.BREVO_API_KEY,
          'content-type': 'application/json'
        }
      });
      logger.info(`Alert email sent via Brevo HTTP API to ${email}`);
      return { success: true, provider: 'brevo' };
    } catch (err) {
      logger.error(`Brevo alert send error: ${err.response?.data?.message || err.message}`);
    }
  }

  // ── Option B: Resend HTTP REST API (HTTPS port 443 — bypasses SMTP blocks) ──
  if (process.env.RESEND_API_KEY) {
    try {
      const fromEmail = process.env.RESEND_SENDER_EMAIL || 'onboarding@resend.dev';
      await axios.post('https://api.resend.com/emails', {
        from: `IOC Sentinel Alerts <${fromEmail}>`,
        to: email,
        subject,
        html: htmlContent
      }, {
        headers: {
          'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
          'Content-Type': 'application/json'
        }
      });
      logger.info(`Alert email sent via Resend HTTP API to ${email}`);
      return { success: true, provider: 'resend' };
    } catch (err) {
      logger.error(`Resend alert send error: ${err.response?.data?.message || err.message}`);
    }
  }

  // ── Option C: Nodemailer SMTP (Gmail / Custom / Ethereal) ─────────────────
  try {
    const transport = await getTransporter();
    if (!transport) {
      logger.warn(`No email transporter available. Alert logged to console.`);
      return { success: false, mode: 'console-fallback' };
    }

    const mailOptions = {
      from: `"IOC Sentinel Alerts 🛡️" <${process.env.SMTP_FROM || process.env.SMTP_USER || 'noreply@iocsentinel.io'}>`,
      to:   email,
      subject,
      text: textContent,
      html: htmlContent,
    };

    const info = await transport.sendMail(mailOptions);
    return info;
  } catch (err) {
    logger.error(`Error sending Alert email via SMTP: ${err.message}`);
    return { success: false, error: err.message };
  }
};

module.exports = { sendOtpEmail, sendAlertEmail };
