// ============================================================
// routes/authRoutes.js — AUTHENTICATION ROUTES
// ============================================================
// POST /api/auth/register  → Create new account
// POST /api/auth/login     → Login, receive JWT
// GET  /api/auth/me        → Get my profile (protected)
// POST /api/auth/logout    → Clear auth cookie
// PUT  /api/auth/password  → Change password (protected)
// ============================================================

const express = require('express');
const router  = express.Router();

const { register, login, getMe, logout, changePassword } = require('../controllers/authController');
const { protect }      = require('../middleware/authMiddleware');
const { authLimiter }  = require('../middleware/rateLimitMiddleware');

// Public routes (no auth required)
// authLimiter applied to login and register to prevent brute force
router.post('/register', authLimiter, register);
router.post('/login',    authLimiter, login);

// Protected routes (JWT required)
router.get('/me',            protect, getMe);
router.post('/logout',       protect, logout);
router.put('/password',      protect, changePassword);

module.exports = router;


// ============================================================
// routes/reportRoutes.js — REPORT ROUTES
// ============================================================
// All routes require authentication.
// Delete requires admin role.
//
// POST   /api/reports              → Create report
// GET    /api/reports              → List reports
// GET    /api/reports/:id          → Get single report
// PUT    /api/reports/:id          → Update report
// POST   /api/reports/:id/publish  → Publish report
// DELETE /api/reports/:id          → Delete report (admin only)
// ============================================================

// Note: This file exports authRoutes.
// reportRoutes.js is created below as a separate file concept
// but shown here for clarity — in your project create it as its own file.
