// src/setupProxy.js
const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  app.use(
    '/einvital', // This is the path prefix that will trigger the proxy
    createProxyMiddleware({
      target: 'https://einv1api.gstsandbox.nic.in', // The base URL of your API
      changeOrigin: true, // Needed for virtual hosted sites
      secure: false, // Set to true for production, false if you have self-signed certs or issues with sandbox
      pathRewrite: {
        '^/einvital': '/einvital', // Rewrite the path if needed, here it's a direct match
      },
    })
  );
};