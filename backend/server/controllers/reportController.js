// ============================================================
// controllers/reportController.js — REPORT MANAGEMENT
// ============================================================
// Reports are analyst-created documents bundling IOCs together
// with findings and recommendations.
//
// Endpoints:
//   POST /api/reports         → Create new report
//   GET  /api/reports         → List all reports (paginated)
//   GET  /api/reports/:id     → Get full report with IOC details
//   PUT  /api/reports/:id     → Update report
//   DELETE /api/reports/:id   → Delete report (admin only)
//   POST /api/reports/:id/publish → Publish a draft report
// ============================================================

const Report = require('../models/Report');
const IOC    = require('../models/IOC');
const logger = require('../utils/logger');

// ── POST /api/reports ─────────────────────────────────────
// Creates a new report from a list of IOC IDs
const createReport = async (req, res, next) => {
  try {
    const { title, description, reportType, iocIds, findings, recommendations, tags } = req.body;

    if (!title) {
      return res.status(400).json({ success: false, message: 'Report title is required' });
    }

    // Validate provided IOC IDs exist in DB
    let resolvedIOCs = [];
    if (iocIds && iocIds.length > 0) {
      resolvedIOCs = await IOC.find({ _id: { $in: iocIds } });

      if (resolvedIOCs.length !== iocIds.length) {
        return res.status(400).json({
          success: false,
          message: `${iocIds.length - resolvedIOCs.length} IOC IDs were not found`,
        });
      }
    }

    // Build summary statistics from the included IOCs
    const summary = buildSummary(resolvedIOCs);

    const report = await Report.create({
      title,
      description,
      reportType,
      iocs:            iocIds || [],
      findings,
      recommendations,
      tags,
      summary,
      createdBy:       req.user.userId,
      status:          'draft',
    });

    // Populate creator info for response
    await report.populate('createdBy', 'username email');

    logger.info(`Report created: "${title}" by ${req.user.username}`);

    res.status(201).json({ success: true, data: report });

  } catch (err) {
    logger.error(`createReport error: ${err.message}`);
    next(err);
  }
};

// ── GET /api/reports ──────────────────────────────────────
const getAllReports = async (req, res, next) => {
  try {
    const {
      page  = 1,
      limit = 10,
      status,
      reportType,
      search,
    } = req.query;

    const filter = {};
    if (status)     filter.status     = status;
    if (reportType) filter.reportType = reportType;
    if (search)     filter.title      = { $regex: search, $options: 'i' };

    const total   = await Report.countDocuments(filter);
    const skip    = (parseInt(page) - 1) * parseInt(limit);

    const reports = await Report.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('createdBy', 'username email')
      .select('-iocs') // Exclude full IOC array from list view (use single report for that)
      .lean();

    res.status(200).json({
      success: true,
      data: {
        reports,
        pagination: {
          total,
          page:       parseInt(page),
          limit:      parseInt(limit),
          totalPages: Math.ceil(total / parseInt(limit)),
        },
      },
    });

  } catch (err) {
    logger.error(`getAllReports error: ${err.message}`);
    next(err);
  }
};

// ── GET /api/reports/:id ──────────────────────────────────
// Full report with IOC details populated
const getReportById = async (req, res, next) => {
  try {
    const report = await Report.findById(req.params.id)
      .populate('createdBy', 'username email')
      .populate({
        path:   'iocs',
        select: 'indicator iocType severity threatScore tags createdAt', // Only key fields
      });

    if (!report) {
      return res.status(404).json({ success: false, message: 'Report not found' });
    }

    res.status(200).json({ success: true, data: report });

  } catch (err) {
    logger.error(`getReportById error: ${err.message}`);
    next(err);
  }
};

// ── PUT /api/reports/:id ──────────────────────────────────
// Update report content. Only the creator or admin can update.
const updateReport = async (req, res, next) => {
  try {
    const report = await Report.findById(req.params.id);

    if (!report) {
      return res.status(404).json({ success: false, message: 'Report not found' });
    }

    // Only creator or admin can edit
    if (
      report.createdBy.toString() !== req.user.userId &&
      req.user.role !== 'admin'
    ) {
      return res.status(403).json({ success: false, message: 'Not authorized to edit this report' });
    }

    // Can't edit published reports (must archive and recreate)
    if (report.status === 'published' && req.user.role !== 'admin') {
      return res.status(400).json({
        success: false,
        message: 'Published reports cannot be edited. Contact an admin.',
      });
    }

    const allowedUpdates = ['title', 'description', 'findings', 'recommendations', 'tags', 'iocs'];
    const updates = {};
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) updates[field] = req.body[field];
    });

    // Recalculate summary if IOCs changed
    if (updates.iocs) {
      const iocs = await IOC.find({ _id: { $in: updates.iocs } });
      updates.summary = buildSummary(iocs);
    }

    const updatedReport = await Report.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    ).populate('createdBy', 'username email');

    res.status(200).json({ success: true, data: updatedReport });

  } catch (err) {
    logger.error(`updateReport error: ${err.message}`);
    next(err);
  }
};

// ── POST /api/reports/:id/publish ────────────────────────
// Transitions report from draft → published
const publishReport = async (req, res, next) => {
  try {
    const report = await Report.findById(req.params.id);

    if (!report) {
      return res.status(404).json({ success: false, message: 'Report not found' });
    }

    if (report.status !== 'draft') {
      return res.status(400).json({
        success: false,
        message: `Report is already ${report.status}`,
      });
    }

    report.status = 'published';
    await report.save();

    logger.info(`Report "${report.title}" published by ${req.user.username}`);
    res.status(200).json({ success: true, message: 'Report published', data: report });

  } catch (err) {
    logger.error(`publishReport error: ${err.message}`);
    next(err);
  }
};

// ── DELETE /api/reports/:id ───────────────────────────────
const deleteReport = async (req, res, next) => {
  try {
    const report = await Report.findByIdAndDelete(req.params.id);

    if (!report) {
      return res.status(404).json({ success: false, message: 'Report not found' });
    }

    logger.info(`Report "${report.title}" deleted by ${req.user.username}`);
    res.status(200).json({ success: true, message: 'Report deleted' });

  } catch (err) {
    logger.error(`deleteReport error: ${err.message}`);
    next(err);
  }
};

// ── Helper: Build Summary Statistics ─────────────────────
// Called when creating/updating reports
const buildSummary = (iocs) => {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const tagFreq = {};

  iocs.forEach(ioc => {
    if (counts[ioc.severity] !== undefined) counts[ioc.severity]++;
    (ioc.tags || []).forEach(tag => {
      tagFreq[tag] = (tagFreq[tag] || 0) + 1;
    });
  });

  // Top 5 tags by frequency
  const topThreatTypes = Object.entries(tagFreq)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([tag]) => tag);

  return {
    totalIOCs:     iocs.length,
    criticalCount: counts.Critical,
    highCount:     counts.High,
    mediumCount:   counts.Medium,
    lowCount:      counts.Low,
    topThreatTypes,
  };
};

module.exports = { createReport, getAllReports, getReportById, updateReport, publishReport, deleteReport };
