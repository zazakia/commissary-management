const { createServer } = require('http');
const { createServerAdapter } = require('@netlify/functions-adapter');
const { app } = require('../app');

const server = createServer(app);
const adapter = createServerAdapter(server);

exports.handler = adapter.handler;
