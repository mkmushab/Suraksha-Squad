/**
 * Optional Zero-Dependency Node.js Dashboard Server for Suraksha Squad.
 * Serves `../static/index.html` and proxies `/api/*` requests to the Python uAgents/FastAPI backend.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.NODE_PORT || 3000;
const PYTHON_API = process.env.PYTHON_API_URL || 'http://127.0.0.1:8000';

const server = http.createServer((req, res) => {
  if (req.url === '/' || req.url === '/index.html') {
    const htmlPath = path.join(__dirname, '..', 'static', 'index.html');
    fs.readFile(htmlPath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(500);
        return res.end('Error loading dashboard HTML');
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(content);
    });
  } else {
    res.writeHead(302, { Location: `${PYTHON_API}${req.url}` });
    res.end();
  }
});

server.listen(PORT, () => {
  console.log(`Suraksha Squad Optional Node.js Dashboard listening on http://localhost:${PORT}`);
});
