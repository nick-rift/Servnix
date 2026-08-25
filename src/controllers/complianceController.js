import complianceService from '../services/complianceService.js';
import logger from '../utils/logger.js';

const complianceController = {
  async getComplianceStatus(req, res) {
    try {
      const status = await complianceService.getComplianceStatus();
      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      logger.error('Compliance status error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getAuditLogs(req, res) {
    try {
      const { limit = 100, offset = 0 } = req.query;
      const logs = await complianceService.getAuditLogs(
        parseInt(limit),
        parseInt(offset)
      );
      res.json({
        success: true,
        data: logs
      });
    } catch (error) {
      logger.error('Audit logs error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getReports(req, res) {
    try {
      const reports = await complianceService.getReports();
      res.json({
        success: true,
        data: reports
      });
    } catch (error) {
      logger.error('Reports error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async generateReport(req, res) {
    try {
      const { type } = req.body;
      const report = await complianceService.generateReport(type || 'full');
      res.json({
        success: true,
        message: 'Report generated successfully',
        data: report
      });
    } catch (error) {
      logger.error('Report generation error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  }
};

export default complianceController;
