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
const { enrichIOC }    = require('../services/enrichmentService');
const { validateIOC }  = require('../utils/iocValidator');
const logger           = require('../utils/logger');

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

    // Step 2: Check if we already have fresh data in DB
    // "Fresh" = enriched within the last 24 hours
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    let existingIOC = await IOC.findOne({
      indicator: indicator.trim(),
      iocType:   validation.type,
    });

    if (existingIOC && existingIOC.lastEnriched > oneDayAgo) {
      logger.info(`Cache hit for ${indicator} — returning stored data`);
      return res.status(200).json({
        success: true,
        cached:  true,
        data:    existingIOC,
      });
    }

    // Step 3: Enrich — call all relevant APIs
    logger.info(`Cache miss for ${indicator} — enriching now`);
    const enrichedData = await enrichIOC(indicator.trim());

    // Step 4: Save or update in MongoDB
    // findOneAndUpdate with upsert: true → creates if not exists
    const savedIOC = await IOC.findOneAndUpdate(
      { indicator: indicator.trim(), iocType: validation.type },
      {
        $set: {
          ...enrichedData,
          submittedBy: req.user?._id || null, // req.user set by authMiddleware
        }
      },
      {
        new:    true,   // Return the updated document (not the old one)
        upsert: true,   // Create if it doesn't exist
        runValidators: true, // Run schema validators on update
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

    // Build MongoDB query filter dynamically
    const filter = { isActive: isActive === 'true' || isActive === true };

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
        { $match: { isActive: true } },
        { $group: { _id: '$severity', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),

      // Count by IOC type
      IOC.aggregate([
        { $match: { isActive: true } },
        { $group: { _id: '$iocType', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),

      // Top countries by IP IOCs
      IOC.aggregate([
        { $match: { iocType: 'ip', 'geoLocation.country': { $ne: null } } },
        { $group: { _id: '$geoLocation.country', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),

      // IOCs per day for the last 30 days (for trend chart)
      IOC.aggregate([
        {
          $match: {
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
        { $match: { isActive: true } },
        { $unwind: '$tags' },
        { $group: { _id: '$tags', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 15 },
      ]),
    ]);

    // Total count
    const totalIOCs = await IOC.countDocuments({ isActive: true });

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
    const ioc = await IOC.findById(req.params.id)
      .populate('submittedBy', 'username email');

    if (!ioc) {
      return res.status(404).json({ success: false, message: 'IOC not found' });
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
    const ioc = await IOC.findByIdAndUpdate(
      req.params.id,
      { $set: { isActive: false } },
      { new: true }
    );

    if (!ioc) {
      return res.status(404).json({ success: false, message: 'IOC not found' });
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
    const ioc = await IOC.findById(req.params.id);
    if (!ioc) {
      return res.status(404).json({ success: false, message: 'IOC not found' });
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

module.exports = {
  searchIOC,
  getAllIOCs,
  getIOCStats,
  getIOCById,
  deleteIOC,
  flagFalsePositive,
};
