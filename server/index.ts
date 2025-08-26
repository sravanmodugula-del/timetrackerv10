import express, { type Request, Response, NextFunction } from "express";
import { createServer } from "http";
import { registerRoutes } from "./routes.js";
import { setupVite, serveStatic, log } from "./vite.js";
import { config } from "dotenv";
import { prisma } from "./db.js";
import path from "path";

// Load environment variables from .env file
config();

// Enhanced logging utility
const LOG_LEVELS = {
  ERROR: '🔴 ERROR',
  WARN: '🟡 WARN',
  INFO: '🔵 INFO',
  DEBUG: '🟢 DEBUG'
};

export function enhancedLog(level: keyof typeof LOG_LEVELS, category: string, message: string, data?: any) {
  const timestamp = new Date().toISOString();
  const logMessage = `${timestamp} ${LOG_LEVELS[level]} [${category}] ${message}`;

  if (data) {
    console.log(logMessage, typeof data === 'object' ? JSON.stringify(data, null, 2) : data);
  } else {
    console.log(logMessage);
  }
}

// IISNode specific error handling
process.on('uncaughtException', (error) => {
  enhancedLog('ERROR', 'PROCESS', 'Uncaught Exception:', {
    message: error.message,
    stack: error.stack,
    name: error.name
  });

  // In IISNode, we don't exit the process as IIS manages it
  if (process.env.iisnode_version) {
    enhancedLog('INFO', 'IISNODE', 'Running under IISNode - error logged but not exiting process');
    return;
  }

  // For non-IISNode environments, still exit
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  const isDbError = reason instanceof Error && 
    (reason.message.includes('terminating connection') || 
     reason.message.includes('database') || 
     reason.message.includes('connection'));

  enhancedLog(isDbError ? 'WARN' : 'ERROR', 'PROCESS', 'Unhandled Rejection:', {
    reason: reason instanceof Error ? {
      message: reason.message,
      stack: reason.stack,
      name: reason.name
    } : reason,
    promise: promise.toString(),
    isDatabaseError: isDbError
  });

  if (!isDbError && !process.env.iisnode_version) {
    process.exit(1);
  }
});

// Environment validation for IISNode
function validateEnvironment() {
  // Check if running under IISNode
  if (process.env.iisnode_version) {
    enhancedLog('INFO', 'IISNODE', `Running under IISNode version ${process.env.iisnode_version}`);

    // IISNode specific environment checks
    const iisNodeRequired = ['WEBSITE_NODE_DEFAULT_VERSION'];
    const missing = iisNodeRequired.filter(varName => !process.env[varName]);

    if (missing.length > 0) {
      enhancedLog('WARN', 'IISNODE', `Missing IISNode environment variables: ${missing.join(', ')}`);
    }
  }

  const required = ['NODE_ENV', 'DATABASE_URL'];
  const missing = required.filter(varName => !process.env[varName]);

  if (missing.length > 0) {
    enhancedLog('ERROR', 'ENV', `Missing required environment variables: ${missing.join(', ')}`);
    if (!process.env.iisnode_version) {
      process.exit(1);
    }
  }

  // Validate NODE_ENV
  if (!process.env.NODE_ENV) {
    process.env.NODE_ENV = 'production'; // Default for IISNode
    enhancedLog('WARN', 'ENV', 'NODE_ENV not set, defaulting to production');
  }

  if (process.env.NODE_ENV !== 'production') {
    enhancedLog('WARN', 'ENV', '⚠️  WARNING: Running in non-production mode with authentication bypass enabled');
  } else {
    enhancedLog('INFO', 'ENV', '✅ Production mode enabled - authentication bypass disabled');
  }

  enhancedLog('INFO', 'ENV', 'Environment validation completed successfully');
}

// Set timezone
process.env.TZ = process.env.TZ || "America/Los_Angeles";
enhancedLog('INFO', 'TIMEZONE', `Set timezone to ${process.env.TZ}`);

// Validate environment before starting application
validateEnvironment();

const app = express();

// IISNode specific middleware
if (process.env.iisnode_version) {
  // Trust IIS proxy
  app.set('trust proxy', true);

  // Set proper paths for IISNode
  app.use(express.static(path.join(__dirname, '../public')));

  enhancedLog('INFO', 'IISNODE', 'IISNode-specific middleware configured');
}

// Security middleware (production-ready)
if (process.env.NODE_ENV === 'production') {
  // Trust proxy for IIS reverse proxy on Windows
  app.set('trust proxy', true);

  // Production security headers for Windows/IIS environment
  app.use((req, res, next) => {
    // Don't set headers if IISNode is handling them via web.config
    if (!process.env.iisnode_version) {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });
}

// Enhanced middleware for better request handling
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  // Enhanced request logging
  if (path.startsWith("/api")) {
    enhancedLog('DEBUG', 'REQUEST', `Incoming ${req.method} ${path}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      query: req.query,
      body: req.method !== 'GET' && req.body ? req.body : undefined,
      sessionId: req.sessionID,
      authenticated: req.isAuthenticated ? req.isAuthenticated() : false,
      iisnode: !!process.env.iisnode_version
    });
  }

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);

      // Enhanced response logging for errors
      if (res.statusCode >= 400) {
        enhancedLog('ERROR', 'RESPONSE', `Error response for ${req.method} ${path}`, {
          status: res.statusCode,
          duration: `${duration}ms`,
          response: capturedJsonResponse,
          request: {
            query: req.query,
            body: req.body,
            ip: req.ip,
            userAgent: req.get('User-Agent')
          }
        });
      }
    }
  });

  next();
});

(async () => {
  const server = createServer(app);

  // Test database connection on startup
  async function startServer() {
    try {
      // Test database connection
      await prisma.user.findFirst().catch(() => {
        console.log('Database connection test - tables may not exist yet, run prisma db push if needed');
      });

      // Get port - always use 3000 for reverse proxy setup
      const port = 3000;

      // Always bind to all interfaces for reverse proxy
      const host = '0.0.0.0';

      app.listen(port, host, () => {
        console.log(`Server running on ${host}:${port}`);
      });
      
      enhancedLog('INFO', 'SERVER', `Server started successfully on ${host}:${port}`, {
        port: port,
        environment: process.env.NODE_ENV,
        timezone: process.env.TZ,
        host: host,
        platform: 'Windows Server + IIS Reverse Proxy',
        database: process.env.DATABASE_URL ? 'HUB-SQL1TST-LIS' : 'Not configured',
        reverseProxy: true
      });
      log(`serving on ${host}:${port} (reverse proxy setup)`);
    } catch (error) {
      enhancedLog('ERROR', 'SERVER', 'Failed to start server:', error);
      if (!process.env.iisnode_version) {
        process.exit(1);
      }
    }
  }

  await registerRoutes(app);

  app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    // Enhanced error logging
    enhancedLog('ERROR', 'EXPRESS', 'Express error middleware triggered:', {
      error: {
        message: err.message,
        stack: err.stack,
        name: err.name,
        code: err.code,
        status: status
      },
      request: {
        method: req.method,
        path: req.path,
        query: req.query,
        body: req.body,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        sessionId: req.sessionID,
        authenticated: req.isAuthenticated ? req.isAuthenticated() : false
      },
      iisnode: !!process.env.iisnode_version
    });

    res.status(status).json({ 
      message,
      error: process.env.NODE_ENV === 'development' ? {
        name: err.name,
        stack: err.stack
      } : undefined
    });
  });

  // Setup Vite for development or serve static for production
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // Start server (unless under IISNode)
  if (!process.env.iisnode_version) {
    startServer();
  } else {
    // For IISNode, just ensure the app is ready
    await startServer();
  }
})();

// Export the app for IISNode
export default app;