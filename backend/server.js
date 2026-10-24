// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const config = require('./src/config');
const { createApp } = require('./src/app');

const app = createApp();

// Render assigns PORT at runtime; bind to 0.0.0.0 so its proxy can reach us.
const server = app.listen(config.port, '0.0.0.0', () => {
  console.log(`DepVault API ${config.version} running on port ${config.port} (AI ${config.ai.url ? 'enabled' : 'disabled'})`);
});

server.requestTimeout = 90 * 1000;
server.headersTimeout = 20 * 1000;

function shutdown(signal) {
  console.log(`${signal} received, closing server`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
