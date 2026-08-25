import cron from 'node-cron';
import securityService from './securityService.js';
import logger from '../utils/logger.js';

const setupScheduledTasks = (io) => {
  // Daily Security Scan - 2:00 AM UTC
  cron.schedule('0 2 * * *', async () => {
    logger.info('🔍 Starting daily security scan...');
    try {
      const vulns = await securityService.scanVulnerabilities();
      io.emit('security:scan-complete', vulns);
    } catch (error) {
      logger.error('Daily scan failed:', error);
    }
  });

  // Weekly Deep Scan - Monday 3:00 AM UTC
  cron.schedule('0 3 * * 1', async () => {
    logger.info('🔍 Starting weekly deep scan...');
    try {
      const result = await securityService.initiateFullScan('full');
      io.emit('security:deep-scan-started', result);
    } catch (error) {
      logger.error('Weekly scan failed:', error);
    }
  });

  // Firewall Check - Every hour
  cron.schedule('0 * * * *', async () => {
    try {
      const firewallStatus = await securityService.getFirewallStatus();
      io.emit('security:firewall-update', firewallStatus);
    } catch (error) {
      logger.error('Firewall check failed:', error);
    }
  });

  // USB Device Check - Every 5 minutes
  cron.schedule('*/5 * * * *', async () => {
    try {
      const usbDevices = await securityService.getUSBDevices();
      if (usbDevices.totalUSBDevices > 0) {
        io.emit('security:usb-devices-detected', usbDevices);
        logger.warn(`⚠️ USB Devices detected: ${usbDevices.totalUSBDevices}`);
      }
    } catch (error) {
      logger.error('USB check failed:', error);
    }
  });

  logger.info('✅ Scheduled security tasks initialized');
};

export { setupScheduledTasks };
