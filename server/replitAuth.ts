import passport from "passport";
import session from "express-session";
import type { Express, RequestHandler, Request, Response } from "express";
import connectPg from "connect-pg-simple";
import { upsertUser, getUserById } from "./storage";
import { createSamlStrategy, generateSamlMetadata } from "./auth/saml";
import { config } from "dotenv";
import * as db from "./db"; // Assuming db is imported and correctly configured

// Load environment variables
config();

export function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1000; // 1 week
  const isProduction = process.env.NODE_ENV === 'production';

  // Validate critical session environment variables
  if (!process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET environment variable is required');
  }

  if (isProduction && process.env.SESSION_SECRET.length < 32) {
    console.warn('⚠️  WARNING: SESSION_SECRET should be at least 32 characters for production security');
  }

  // Use PostgreSQL session store for production, memory for development
  if (isProduction && process.env.DATABASE_URL) {
    const pgStore = connectPg(session);
    const sessionStore = new pgStore({
      conString: process.env.DATABASE_URL,
      createTableIfMissing: true,
      ttl: sessionTtl,
      tableName: "sessions",
    });

    return session({
      secret: process.env.SESSION_SECRET!,
      store: sessionStore,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: isProduction,
        maxAge: sessionTtl,
        sameSite: 'lax',
      },
      name: 'timetracker.sid',
    });
  } else {
    // Development settings
    return session({
      secret: process.env.SESSION_SECRET!,
      resave: true,
      saveUninitialized: true,
      rolling: true,
      cookie: {
        httpOnly: false,
        secure: false,
        maxAge: sessionTtl,
        sameSite: 'lax',
      },
      name: 'timetracker.sid',
    });
  }
}

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

  // Setup SAML strategy if enabled
  if (process.env.SAML_ENABLED === 'true') {
    const samlStrategy = createSamlStrategy();
    if (samlStrategy) {
      passport.use('saml', samlStrategy);
      console.log('🔐 SAML authentication strategy configured');
    }
  }

  passport.serializeUser((user: Express.User, cb) => cb(null, user));
  passport.deserializeUser((user: Express.User, cb) => cb(null, user));

  // SAML Login route
  app.get("/api/login", (req, res, next) => {
    console.log("🔐 Login attempt - redirecting to SAML");
    if (process.env.SAML_ENABLED === 'true') {
      passport.authenticate('saml', {
        successRedirect: '/',
        failureRedirect: '/login?error=saml_failed'
      })(req, res, next);
    } else {
      res.status(503).json({ message: "Authentication not configured" });
    }
  });

  // SAML Callback route
  app.post("/api/callback", (req, res, next) => {
    console.log("🔗 SAML callback received");
    passport.authenticate('saml', (err: any, user: any, info: any) => {
      if (err) {
        console.error("❌ SAML callback error:", err);
        return res.redirect("/login?error=saml_error");
      }

      if (!user) {
        console.error("❌ SAML callback failed - no user:", info);
        return res.redirect("/login?error=saml_failed");
      }

      req.logIn(user, (loginErr) => {
        if (loginErr) {
          console.error("❌ Login error:", loginErr);
          return res.redirect("/login?error=login_failed");
        }

        console.log("✅ SAML callback successful, redirecting to /");
        return res.redirect("/");
      });
    })(req, res, next);
  });

  // SAML Metadata endpoint
  app.get("/api/saml/metadata", (req, res) => {
    if (process.env.SAML_ENABLED === 'true') {
      res.type('application/xml');
      res.send(generateSamlMetadata());
    } else {
      res.status(404).json({ message: "SAML not enabled" });
    }
  });

  // Logout route
  app.get("/api/logout", (req, res) => {
    req.logout(() => {
      req.session.destroy(() => {
        res.redirect("/login");
      });
    });
  });
}

// Enhanced authentication logging
function authLog(level: 'INFO' | 'WARN' | 'ERROR' | 'DEBUG', message: string, data?: any) {
  const timestamp = new Date().toISOString();
  const emoji = level === 'ERROR' ? '🔴' : level === 'WARN' ? '🟡' : level === 'INFO' ? '🔵' : '🟢';
  const logMessage = `${timestamp} ${emoji} [AUTH] ${message}`;

  if (data) {
    console.log(logMessage, typeof data === 'object' ? JSON.stringify(data, null, 2) : data);
  } else {
    console.log(logMessage);
  }
}

export const isAuthenticated: RequestHandler = async (req, res, next) => {
  try {
    authLog('DEBUG', `Authentication check for ${req.method} ${req.path}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: req.sessionID,
      hasSession: !!req.session,
      isAuthenticated: req.isAuthenticated ? req.isAuthenticated() : false
    });

    // CRITICAL SECURITY: Only allow test user in development mode
    if (process.env.NODE_ENV === 'development' && (!req.isAuthenticated() || !req.user)) {
      authLog('DEBUG', 'Development mode: Creating test admin user');
      authLog('WARN', 'SECURITY: Authentication bypass active - DO NOT USE IN PRODUCTION');

      req.user = {
        claims: {
          sub: "test-admin-user",
          email: "admin@test.com",
          first_name: "Test",
          last_name: "Admin"
        },
        authSource: 'development',
        id: "test-admin-user" // Added id for getUser method
      };

      try {
        await upsertUser({
          id: "test-admin-user",
          email: "admin@test.com", 
          firstName: "Test",
          lastName: "Admin",
          profileImageUrl: null,
        });

        const currentUser = await getUserById("test-admin-user");
        const currentRole = currentUser?.role || "admin";

        if (!currentUser) {
          authLog('INFO', 'Test admin user created successfully');
        } else {
          authLog('INFO', `Test user authenticated with current role: ${currentRole}`);
        }
      } catch (dbError) {
        authLog('ERROR', 'Failed to setup test user:', dbError);
      }

      return next();
    }

    if (!req.isAuthenticated() || !req.user) {
      authLog('WARN', 'Unauthorized access attempt', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        sessionId: req.sessionID
      });
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = req.user as any;
    authLog('DEBUG', 'User authenticated', {
      userId: user.claims?.sub || 'unknown',
      email: user.claims?.email || 'unknown',
      sessionId: req.sessionID,
      authSource: user.authSource || 'unknown'
    });

    authLog('DEBUG', 'Authentication successful, proceeding to next middleware');
    return next();

  } catch (error) {
    authLog('ERROR', 'Authentication middleware error:', {
      error: error instanceof Error ? {
        message: error.message,
        stack: error.stack,
        name: error.name
      } : error,
      request: {
        method: req.method,
        path: req.path,
        ip: req.ip,
        sessionId: req.sessionID
      }
    });
    return res.status(500).json({ message: "Internal server error" });
  }
};

// Assuming an auth controller object exists or will be created.
// This part needs to be integrated where the checkAuth and getUser are used.
// For demonstration, let's assume it's part of a larger auth module.
const authController = {
  checkAuth: (req: Request, res: Response) => {
    if (req.user) {
      res.json({ authenticated: true, user: req.user });
    } else {
      res.status(401).json({ authenticated: false });
    }
  },

  getUser: async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      // Ensure req.user has an 'id' property that matches the database schema
      const userId = (req.user as any).id || (req.user as any).claims?.sub;
      if (!userId) {
        console.error('User ID not found in session.');
        return res.status(401).json({ message: "User identifier missing" });
      }

      // Get user from database with proper error handling
      const user = await prisma.user.findFirst({
        where: {
          id: userId
        }
      });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json(user);
    } catch (error) {
      console.error('Error fetching user:', error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  },
};