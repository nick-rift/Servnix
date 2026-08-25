import logger from '../utils/logger.js';

const authenticate = (req, res, next) => {
  // For internal-only dashboard, allow localhost/127.0.0.1
  const clientIP = req.ip || req.connection.remoteAddress;
  const isLocalhost = clientIP === '127.0.0.1' || clientIP === 'localhost' || clientIP.includes('127.0.0.1') || clientIP.includes('::1');

  if (!isLocalhost) {
    logger.warn(`Unauthorized access attempt from IP: ${clientIP}`);
    return res.status(403).json({
      success: false,
      error: 'Access restricted to localhost only'
    });
  }

  next();
};

export { authenticate };
