import securityService from '../services/securityService.js';
import logger from '../utils/logger.js';

const securityController = {
  async getVulnerabilities(req, res) {
    try {
      const vulns = await securityService.scanVulnerabilities();
      res.json({
        success: true,
        data: vulns,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error('Vulnerability scan error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getFirewallStatus(req, res) {
    try {
      const status = await securityService.getFirewallStatus();
      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      logger.error('Firewall status error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getSSLStatus(req, res) {
    try {
      const status = await securityService.getSSLStatus();
      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      logger.error('SSL status error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getConnectedDevices(req, res) {
    try {
      const devices = await securityService.getConnectedDevices();
      res.json({
        success: true,
        data: devices
      });
    } catch (error) {
      logger.error('Devices scan error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async blockDevice(req, res) {
    try {
      const { deviceId, reason } = req.body;
      if (!deviceId) {
        return res.status(400).json({ success: false, error: 'Device ID required' });
      }

      const result = await securityService.blockDevice(deviceId, reason);
      logger.warn(`Device blocked: ${deviceId}. Reason: ${reason}`);
      
      res.json({
        success: true,
        message: `Device ${deviceId} has been blocked`,
        data: result
      });
    } catch (error) {
      logger.error('Device block error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async initiateScan(req, res) {
    try {
      const { scanType } = req.body;
      const result = await securityService.initiateFullScan(scanType || 'full');
      
      res.json({
        success: true,
        message: 'Security scan initiated',
        data: result
      });
    } catch (error) {
      logger.error('Scan initiation error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getScanHistory(req, res) {
    try {
      const history = await securityService.getScanHistory();
      res.json({
        success: true,
        data: history
      });
    } catch (error) {
      logger.error('Scan history error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }
};

export default securityController;
