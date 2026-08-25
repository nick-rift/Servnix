import networkService from '../services/networkService.js';
import logger from '../utils/logger.js';

const networkController = {
  async getActiveConnections(req, res) {
    try {
      const connections = await networkService.getActiveConnections();
      res.json({
        success: true,
        data: connections,
        count: connections.length
      });
    } catch (error) {
      logger.error('Active connections error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getNetworkTraffic(req, res) {
    try {
      const traffic = await networkService.getNetworkTraffic();
      res.json({
        success: true,
        data: traffic
      });
    } catch (error) {
      logger.error('Network traffic error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getDNSQueries(req, res) {
    try {
      const queries = await networkService.getDNSQueries();
      res.json({
        success: true,
        data: queries
      });
    } catch (error) {
      logger.error('DNS queries error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async blockIP(req, res) {
    try {
      const { ip, reason } = req.body;
      if (!ip) {
        return res.status(400).json({ success: false, error: 'IP address required' });
      }

      const result = await networkService.blockIP(ip, reason);
      logger.warn(`IP blocked: ${ip}. Reason: ${reason}`);
      
      res.json({
        success: true,
        message: `IP ${ip} has been blocked`,
        data: result
      });
    } catch (error) {
      logger.error('Block IP error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getBlockedIPs(req, res) {
    try {
      const blockedIPs = await networkService.getBlockedIPs();
      res.json({
        success: true,
        data: blockedIPs
      });
    } catch (error) {
      logger.error('Blocked IPs error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }
};

export default networkController;
