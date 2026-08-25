import securityService from '../services/securityService.js';
import networkService from '../services/networkService.js';
import logger from '../utils/logger.js';

const dashboardController = {
  async getOverview(req, res) {
    try {
      const [securityStatus, networkStatus, metrics] = await Promise.all([
        securityService.getSecurityStatus(),
        networkService.getNetworkStatus(),
        dashboardController.getMetrics(req, res)
      ]);

      res.json({
        success: true,
        data: {
          security: securityStatus,
          network: networkStatus,
          timestamp: new Date().toISOString()
        }
      });
    } catch (error) {
      logger.error('Dashboard overview error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getStatus(req, res) {
    try {
      const status = {
        firewall: await securityService.getFirewallStatus(),
        sslTls: await securityService.getSSLStatus(),
        vulnerabilities: await securityService.getVulnerabilitiesCount(),
        networkConnections: await networkService.getActiveConnectionsCount(),
        lastScan: await securityService.getLastScanTime(),
        threatLevel: await securityService.calculateThreatLevel()
      };

      res.json({
        success: true,
        data: status
      });
    } catch (error) {
      logger.error('Status endpoint error:', error);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  async getMetrics(req, res) {
    try {
      const metrics = {
        securityScore: await securityService.calculateSecurityScore(),
        complianceScore: await securityService.calculateComplianceScore(),
        vulnerabilityTrend: await securityService.getVulnerabilityTrend(),
        uptime: await securityService.getSystemUptime(),
        cpuUsage: await securityService.getCPUUsage(),
        memoryUsage: await securityService.getMemoryUsage(),
        diskUsage: await securityService.getDiskUsage()
      };

      if (res && res.json) {
        res.json({
          success: true,
          data: metrics
        });
      }
      return metrics;
    } catch (error) {
      logger.error('Metrics endpoint error:', error);
      if (res && res.status) {
        res.status(500).json({ success: false, error: error.message });
      }
      return null;
    }
  }
};

export default dashboardController;
