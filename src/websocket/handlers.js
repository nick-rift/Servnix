const setupWebSocket = (io) => {
  io.on('connection', (socket) => {
    console.log(`🔌 Client connected: ${socket.id}`);

    // Join default room
    socket.join('dashboard');
    socket.join('security');
    socket.join('network');

    socket.on('disconnect', () => {
      console.log(`❌ Client disconnected: ${socket.id}`);
    });

    // Listen for action requests
    socket.on('security:block-device', (data) => {
      console.log(`📛 Block device request:`, data);
      io.to('dashboard').emit('alert:device-blocked', {
        deviceId: data.deviceId,
        reason: data.reason,
        timestamp: new Date().toISOString()
      });
    });

    socket.on('security:block-ip', (data) => {
      console.log(`📛 Block IP request:`, data);
      io.to('dashboard').emit('alert:ip-blocked', {
        ip: data.ip,
        reason: data.reason,
        timestamp: new Date().toISOString()
      });
    });

    socket.on('security:initiate-scan', (data) => {
      console.log(`🔍 Scan initiation:`, data);
      io.to('dashboard').emit('status:scan-started', {
        scanType: data.scanType,
        startTime: new Date().toISOString()
      });
    });
  });
};

export { setupWebSocket };
