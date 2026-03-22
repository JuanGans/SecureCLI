/**
 * SecureCLI HTTP API Server
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const { URL } = require('url');
const Orchestrator = require('../core/orchestrator');

function writeJson(res, statusCode, payload, corsOrigin) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(JSON.stringify(payload));
}

function parseJsonBody(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let data = '';

    req.on('data', chunk => {
      data += chunk;
      if (Buffer.byteLength(data, 'utf8') > maxBytes) {
        reject(new Error('Payload too large'));
      }
    });

    req.on('end', () => {
      if (!data) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(data));
      } catch (err) {
        reject(new Error('Invalid JSON body'));
      }
    });

    req.on('error', err => reject(err));
  });
}

function buildApiDocs(port) {
  return {
    service: 'SecureCLI API Server',
    version: '1.0.0',
    endpoints: [
      {
        method: 'GET',
        path: '/health',
        description: 'Health check endpoint',
      },
      {
        method: 'GET',
        path: '/docs',
        description: 'API endpoint documentation',
      },
      {
        method: 'POST',
        path: '/scan',
        description: 'Run vulnerability scan on file/folder path',
        body: {
          target: 'string (required, absolute/relative path)',
          verbose: 'boolean (optional, default false)',
          output: 'string (optional, save report path)',
        },
      },
    ],
    example: {
      url: `http://localhost:${port}/scan`,
      body: {
        target: './src',
        verbose: true,
      },
    },
  };
}

function parseFindings(jsonReport) {
  try {
    return JSON.parse(jsonReport);
  } catch (err) {
    return [];
  }
}

function startApiServer(options = {}) {
  const port = Number(options.port || process.env.PORT || 3001);
  const host = options.host || process.env.HOST || '0.0.0.0';
  const corsOrigin = options.corsOrigin || process.env.CORS_ORIGIN || '*';

  const server = http.createServer(async (req, res) => {
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (req.method === 'OPTIONS') {
      writeJson(res, 200, { ok: true }, corsOrigin);
      return;
    }

    if (req.method === 'GET' && parsedUrl.pathname === '/health') {
      writeJson(
        res,
        200,
        {
          ok: true,
          service: 'securecli-api',
          status: 'healthy',
          timestamp: new Date().toISOString(),
        },
        corsOrigin
      );
      return;
    }

    if (req.method === 'GET' && parsedUrl.pathname === '/docs') {
      writeJson(res, 200, buildApiDocs(port), corsOrigin);
      return;
    }

    if (req.method === 'POST' && parsedUrl.pathname === '/scan') {
      try {
        const body = await parseJsonBody(req);
        const target = (body.target || '').trim();

        if (!target) {
          writeJson(res, 400, { ok: false, error: 'Field "target" is required' }, corsOrigin);
          return;
        }

        const resolvedTarget = path.resolve(target);
        if (!fs.existsSync(resolvedTarget)) {
          writeJson(
            res,
            400,
            {
              ok: false,
              error: `Target path does not exist: ${resolvedTarget}`,
            },
            corsOrigin
          );
          return;
        }

        const verbose = Boolean(body.verbose);
        const outputPath = typeof body.output === 'string' ? body.output : null;

        const start = Date.now();
        const orchestrator = new Orchestrator({ verbose, format: 'json' });
        const result = await orchestrator.orchestrate(resolvedTarget, outputPath);
        const findings = parseFindings(result.reports.json);

        writeJson(
          res,
          200,
          {
            ok: true,
            meta: {
              target: resolvedTarget,
              durationMs: Date.now() - start,
              findingsCount: findings.length,
              summary: result.summary,
            },
            findings,
          },
          corsOrigin
        );
      } catch (error) {
        const status = error.message === 'Invalid JSON body' || error.message === 'Payload too large' ? 400 : 500;
        writeJson(res, status, { ok: false, error: error.message }, corsOrigin);
      }
      return;
    }

    writeJson(res, 404, { ok: false, error: 'Route not found' }, corsOrigin);
  });

  server.listen(port, host, () => {
    console.log(`\nSecureCLI API server running on http://${host}:${port}`);
    console.log(`Health check: http://${host}:${port}/health`);
    console.log(`API docs:     http://${host}:${port}/docs\n`);
  });

  return server;
}

module.exports = {
  startApiServer,
};
