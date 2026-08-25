import express from 'express';
import dashboardController from '../controllers/dashboardController.js';
import securityController from '../controllers/securityController.js';
import networkController from '../controllers/networkController.js';
import complianceController from '../controllers/complianceController.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// Authentication middleware
router.use(authenticate);

// Dashboard endpoints
router.get('/dashboard/overview', dashboardController.getOverview);
router.get('/dashboard/status', dashboardController.getStatus);
router.get('/dashboard/metrics', dashboardController.getMetrics);

// Security endpoints
router.get('/security/vulnerabilities', securityController.getVulnerabilities);
router.get('/security/firewall', securityController.getFirewallStatus);
router.get('/security/ssl-tls', securityController.getSSLStatus);
router.get('/security/devices', securityController.getConnectedDevices);
router.post('/security/device/block', securityController.blockDevice);
router.post('/security/scan', securityController.initiateScan);
router.get('/security/scan-history', securityController.getScanHistory);

// Network endpoints
router.get('/network/connections', networkController.getActiveConnections);
router.get('/network/traffic', networkController.getNetworkTraffic);
router.get('/network/dns-queries', networkController.getDNSQueries);
router.post('/network/block-ip', networkController.blockIP);
router.get('/network/blocked-ips', networkController.getBlockedIPs);

// Compliance endpoints
router.get('/compliance/status', complianceController.getComplianceStatus);
router.get('/compliance/audit-logs', complianceController.getAuditLogs);
router.get('/compliance/reports', complianceController.getReports);
router.post('/compliance/generate-report', complianceController.generateReport);

export default router;
