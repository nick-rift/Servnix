import express from 'express';
import helmet from 'helmet';
import dotenv from 'dotenv';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import path from 'path';
import { fileURLToPath } from 'url';
import apiRoutes from './api/routes.js';
import { setupWebSocket } from './websocket/handlers.js';
import { setupScheduledTasks } from './services/scheduler.js';
import logger from './utils/logger.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Security Middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// CORS for internal use only
app.use((req, res, next) => {
  const allowedHosts = [
    'localhost:3000',
    '127.0.0.1:3000',
    process.env.DASHBOARD_HOST || 'localhost'
  ];

  const origin = req.headers.origin;
  if (allowedHosts.some(host => origin && origin.includes(host))) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }

  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, '../public')));

// API Routes
app.use('/api', apiRoutes);

// WebSocket setup
setupWebSocket(io);

// Scheduled tasks
setupScheduledTasks(io);

// Error handling
app.use((err, req, res, next) => {
  logger.error('Request error:', err);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error'
  });
});

const PORT = process.env.DASHBOARD_PORT || 3000;
const HOST = process.env.DASHBOARD_HOST || 'localhost';

server.listen(PORT, HOST, () => {
  logger.info(`🛡️  Servnix Dashboard listening on http://${HOST}:${PORT}`);
  logger.info('✅ Security monitoring active');
});

export { app, io };
