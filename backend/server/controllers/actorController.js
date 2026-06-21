// ============================================================
// controllers/actorController.js — THREAT ACTOR CRUD
// ============================================================
// Manages threat actor profiles and their linked IOCs.
//
// Endpoints:
//   GET    /api/actors           → List all actors (paginated, searchable)
//   POST   /api/actors           → Create new actor profile
//   GET    /api/actors/:id       → Get actor details with populated IOCs
//   PUT    /api/actors/:id       → Full update actor profile
//   DELETE /api/actors/:id       → Delete actor (admin only)
//   POST   /api/actors/:id/iocs  → Link IOC(s) to actor
//   DELETE /api/actors/:id/iocs/:iocId → Unlink IOC from actor
//   GET    /api/actors/stats     → Summary stats for dashboard
// ============================================================

const ThreatActor = require('../models/ThreatActor');
const IOC         = require('../models/IOC');
const logger      = require('../utils/logger');

// ── GET /api/actors ───────────────────────────────────────
// List all actors with optional search, filter, and pagination
const getActors = async (req, res, next) => {
  try {
    const {
      page       = 1,
      limit      = 20,
      search     = '',
      country    = '',
      motivation = '',
      actorType  = '',
      isActive   = '',
    } = req.query;

    const filter = {};

    // Full-text search across name, aliases, description
    if (search) {
      filter.$text = { $search: search };
    }

    if (country)    filter.country    = new RegExp(country, 'i');
    if (motivation) filter.motivation = motivation;
    if (actorType)  filter.actorType  = actorType;
    if (isActive !== '') filter.isActive = isActive === 'true';

    const skip  = (Number(page) - 1) * Number(limit);
    const total = await ThreatActor.countDocuments(filter);

    const actors = await ThreatActor
      .find(filter)
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .select('-linkedIOCs')   // exclude full array for list view
      .lean();

    // Inject iocCount manually (since we excluded linkedIOCs)
    const actorsWithCount = await Promise.all(
      actors.map(async (a) => {
        const count = await ThreatActor.aggregate([
          { $match: { _id: a._id } },
          { $project: { iocCount: { $size: '$linkedIOCs' } } },
        ]);
        return { ...a, iocCount: count[0]?.iocCount || 0 };
      })
    );

    res.json({
      success: true,
      data: actorsWithCount,
      pagination: {
        total,
        page:  Number(page),
        limit: Number(limit),
        pages: Math.ceil(total / Number(limit)),
      },
    });
  } catch (err) {
    next(err);
  }
};

// ── POST /api/actors ──────────────────────────────────────
// Create a new threat actor profile
const createActor = async (req, res, next) => {
  try {
    const {
      name, aliases, country, countryCode,
      motivation, actorType, confidence,
      ttps, description, targetSectors, campaigns,
    } = req.body;

    if (!name?.trim()) {
      return res.status(400).json({ success: false, message: 'Actor name is required' });
    }

    // Check for duplicate name
    const existing = await ThreatActor.findOne({ name: name.trim() });
    if (existing) {
      return res.status(409).json({
        success: false,
        message: `Threat actor "${name}" already exists`,
      });
    }

    const actor = await ThreatActor.create({
      name:          name.trim(),
      aliases:       aliases || [],
      country:       country || 'Unknown',
      countryCode:   countryCode || null,
      motivation:    motivation || 'unknown',
      actorType:     actorType || 'unknown',
      confidence:    confidence ?? 50,
      ttps:          ttps || [],
      description:   description || '',
      targetSectors: targetSectors || [],
      campaigns:     campaigns || [],
      createdBy:     req.user.userId,
    });

    logger.info(`New threat actor created: ${actor.name} by ${req.user.username}`);

    res.status(201).json({ success: true, data: actor });
  } catch (err) {
    next(err);
  }
};

// ── GET /api/actors/:id ───────────────────────────────────
// Fetch single actor with fully populated linked IOCs
const getActorById = async (req, res, next) => {
  try {
    const actor = await ThreatActor
      .findById(req.params.id)
      .populate({
        path:   'linkedIOCs',
        select: 'indicator iocType severity threatScore tags createdAt mitreTechniques',
      })
      .populate('createdBy', 'username email');

    if (!actor) {
      return res.status(404).json({ success: false, message: 'Threat actor not found' });
    }

    res.json({ success: true, data: actor });
  } catch (err) {
    next(err);
  }
};

// ── PUT /api/actors/:id ───────────────────────────────────
// Full update — replace fields (only non-null provided values)
const updateActor = async (req, res, next) => {
  try {
    const allowedFields = [
      'name', 'aliases', 'country', 'countryCode',
      'motivation', 'actorType', 'confidence',
      'ttps', 'description', 'targetSectors', 'campaigns', 'isActive',
    ];

    const updates = {};
    allowedFields.forEach((field) => {
      if (req.body[field] !== undefined) updates[field] = req.body[field];
    });

    const actor = await ThreatActor.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    ).populate('linkedIOCs', 'indicator iocType severity threatScore');

    if (!actor) {
      return res.status(404).json({ success: false, message: 'Threat actor not found' });
    }

    logger.info(`Threat actor ${actor.name} updated by ${req.user.username}`);
    res.json({ success: true, data: actor });
  } catch (err) {
    next(err);
  }
};

// ── DELETE /api/actors/:id ────────────────────────────────
// Admin only — permanently remove actor profile
const deleteActor = async (req, res, next) => {
  try {
    const actor = await ThreatActor.findByIdAndDelete(req.params.id);

    if (!actor) {
      return res.status(404).json({ success: false, message: 'Threat actor not found' });
    }

    logger.warn(`Threat actor ${actor.name} deleted by ${req.user.username}`);
    res.json({ success: true, message: `Threat actor "${actor.name}" deleted` });
  } catch (err) {
    next(err);
  }
};

// ── POST /api/actors/:id/iocs ─────────────────────────────
// Link one or more IOC IDs to an actor
const linkIOCs = async (req, res, next) => {
  try {
    const { iocIds } = req.body; // array of IOC ObjectIds

    if (!iocIds || !Array.isArray(iocIds) || iocIds.length === 0) {
      return res.status(400).json({ success: false, message: 'iocIds array is required' });
    }

    // Verify all IOCs exist and belong to this user
    const validIOCs = await IOC.find({
      _id:         { $in: iocIds },
      submittedBy: req.user.userId,
    }).select('_id');

    const validIds = validIOCs.map(i => i._id);

    const actor = await ThreatActor.findByIdAndUpdate(
      req.params.id,
      { $addToSet: { linkedIOCs: { $each: validIds } } },
      { new: true }
    ).populate('linkedIOCs', 'indicator iocType severity threatScore tags');

    if (!actor) {
      return res.status(404).json({ success: false, message: 'Threat actor not found' });
    }

    logger.info(`Linked ${validIds.length} IOCs to actor ${actor.name}`);
    res.json({ success: true, data: actor, linked: validIds.length });
  } catch (err) {
    next(err);
  }
};

// ── DELETE /api/actors/:id/iocs/:iocId ────────────────────
// Unlink a single IOC from an actor
const unlinkIOC = async (req, res, next) => {
  try {
    const actor = await ThreatActor.findByIdAndUpdate(
      req.params.id,
      { $pull: { linkedIOCs: req.params.iocId } },
      { new: true }
    );

    if (!actor) {
      return res.status(404).json({ success: false, message: 'Threat actor not found' });
    }

    res.json({ success: true, message: 'IOC unlinked', data: actor });
  } catch (err) {
    next(err);
  }
};

// ── GET /api/actors/stats ─────────────────────────────────
// Aggregated stats for dashboard widgets
const getActorStats = async (req, res, next) => {
  try {
    const [
      total,
      byMotivation,
      byCountry,
      byType,
    ] = await Promise.all([
      ThreatActor.countDocuments({ isActive: true }),

      ThreatActor.aggregate([
        { $match: { isActive: true } },
        { $group: { _id: '$motivation', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),

      ThreatActor.aggregate([
        { $match: { isActive: true, country: { $ne: 'Unknown' } } },
        { $group: { _id: '$country', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),

      ThreatActor.aggregate([
        { $match: { isActive: true } },
        { $group: { _id: '$actorType', count: { $sum: 1 } } },
      ]),
    ]);

    res.json({
      success: true,
      data: { total, byMotivation, byCountry, byType },
    });
  } catch (err) {
    next(err);
  }
};

module.exports = {
  getActors,
  createActor,
  getActorById,
  updateActor,
  deleteActor,
  linkIOCs,
  unlinkIOC,
  getActorStats,
};
