// ============================================================
// services/socketService.js — REAL-TIME ALERTS SERVICE
// ============================================================

const { Server } = require('socket.io');
const logger = require('../utils/logger');

let io;

const initSocket = (server) => {
  io = new Server(server, {
    cors: {
      origin: "*", // Adjust origins if security policies require it
      methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
      credentials: true
    }
  });

  io.on('connection', (socket) => {
    logger.info(`🔌 Client connected to Socket.io: ${socket.id}`);

    // Client registers their authenticated userId to receive targeted alerts
    socket.on('authenticate', (userId) => {
      if (userId) {
        const roomName = `user_${userId}`;
        socket.join(roomName);
        logger.info(`🔑 Socket ${socket.id} authenticated for user room: ${roomName}`);
      }
    });

    socket.on('disconnect', () => {
      logger.info(`🔌 Client disconnected from Socket.io: ${socket.id}`);
    });
  });

  return io;
};

const getIO = () => io;

/**
 * Emit an alert event to a specific user room.
 */
const emitToUser = (userId, event, data) => {
  if (io) {
    const roomName = `user_${userId}`;
    io.to(roomName).emit(event, data);
    logger.info(`📡 Alert emitted to room ${roomName} for event '${event}'`);
  } else {
    logger.warn('⚠️ Cannot emit alert; Socket.io is not initialized');
  }
};

/**
 * Broadcast an event to all connected sockets.
 */
const emitToAll = (event, data) => {
  if (io) {
    io.emit(event, data);
    logger.info(`📡 Broadcasted event '${event}' to all sockets`);
  } else {
    logger.warn('⚠️ Cannot broadcast; Socket.io is not initialized');
  }
};

module.exports = {
  initSocket,
  getIO,
  emitToUser,
  emitToAll
};
