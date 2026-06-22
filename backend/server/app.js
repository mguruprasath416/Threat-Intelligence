require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const morgan  = require('morgan');

const iocRoutes    = require('./routes/iocRoutes');
const authRoutes   = require('./routes/authRoutes');
const reportRoutes = require('./routes/reportRoutes');
const actorRoutes  = require('./routes/actorRoutes');
const taxiiRoutes  = require('./routes/taxiiRoutes');
const watchlistRoutes = require('./routes/watchlistRoutes');
const alertRoutes = require('./routes/alertRoutes');
const pasteMonitorRoutes = require('./routes/pasteMonitorRoutes');

const errorMiddleware     = require('./middleware/errorMiddleware');
const rateLimitMiddleware = require('./middleware/rateLimitMiddleware');
const logger              = require('./utils/logger');

const app = express();

app.use(helmet());

app.use(cors({
  origin: function(origin, callback) {
    callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

app.options('*', cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(morgan('combined', {
  stream: { write: (msg) => logger.info(msg.trim()) }
}));

app.use('/api/', rateLimitMiddleware);

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

app.use('/api/ioc',     iocRoutes);
app.use('/api/auth',    authRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/actors',  actorRoutes);
app.use('/api/taxii',   taxiiRoutes);
app.use('/api/watchlist', watchlistRoutes);
app.use('/api/alerts',  alertRoutes);
app.use('/api/paste',   pasteMonitorRoutes);

app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

app.use(errorMiddleware);

module.exports = app;