const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const rootDir = __dirname;
const port = Number(process.env.PORT) || 8000;

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon'
};

function resolveFilePath(requestPath) {
  const safePath = decodeURIComponent(requestPath.split('?')[0].split('#')[0]);
  let filePath = path.join(rootDir, safePath === '/' ? 'index.html' : safePath);

  if (!filePath.startsWith(rootDir)) {
    return null;
  }

  try {
    const stats = fs.statSync(filePath);
    if (stats.isDirectory()) {
      filePath = path.join(filePath, 'index.html');
    }
  } catch {
    if (!path.extname(filePath)) {
      const htmlPath = `${filePath}.html`;
      if (fs.existsSync(htmlPath)) {
        filePath = htmlPath;
      }
    }
  }

  return filePath;
}

const server = http.createServer((req, res) => {
  const filePath = resolveFilePath(req.url || '/');

  if (!filePath) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Forbidden');
    return;
  }

  fs.readFile(filePath, (error, content) => {
    if (error) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = mimeTypes[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type': contentType,
      'Cache-Control': 'no-store'
    });
    res.end(content);
  });
});

server.listen(port, () => {
  console.log(`Password Fortress running at http://localhost:${port}`);
  console.log('Press Ctrl+C to stop the server.');
});
