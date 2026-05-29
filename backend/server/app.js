require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const morgan  = require('morgan');

const iocRoutes    = require('./routes/iocRoutes');
const authRoutes   = require('./routes/authRoutes');
const reportRoutes = require('./routes/reportRoutes');

const errorMiddleware     = require('./middleware/errorMiddleware');
const rateLimitMiddleware = require('./middleware/rateLimitMiddleware');
const logger              = require('./utils/logger');

const app = express();

app.use(helmet());

// ── CORS ──────────────────────────────────────────────────
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://intuitive-liberation-production-ac89.up.railway.app',
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

app.options('*', cors());

// ── Body Parsing ──────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Logging ───────────────────────────────────────────────
app.use(morgan('combined', {
  stream: { write: (msg) => logger.info(msg.trim()) }
}));

// ── Rate Limiting ─────────────────────────────────────────
app.use('/api/', rateLimitMiddleware);

// ── Health Check ──────────────────────────────────────────
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ── API Routes ────────────────────────────────────────────
app.use('/api/ioc',     iocRoutes);
app.use('/api/auth',    authRoutes);
app.use('/api/reports', reportRoutes);

// ── 404 Handler ───────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// ── Global Error Handler ──────────────────────────────────
app.use(errorMiddleware);

module.exports = app;