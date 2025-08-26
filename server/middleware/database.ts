
import { Request, Response, NextFunction } from 'express';
import { prisma, checkDatabaseHealth } from '../db';

// Enhanced database connection middleware with graceful fallback
export async function ensureDatabaseConnection(req: Request, res: Response, next: NextFunction) {
  try {
    // Quick connection test with timeout
    const testPromise = prisma.$queryRaw`SELECT 1`;
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Connection timeout')), 5000);
    });

    await Promise.race([testPromise, timeoutPromise]);
    next();
  } catch (error: any) {
    const isDevelopment = process.env.NODE_ENV !== 'production';
    const isOnPremSqlServer = process.env.DATABASE_URL?.includes('HUB-SQL1TST-LIS');
    
    if (isDevelopment && isOnPremSqlServer) {
      // In development with on-premises SQL Server, continue without database
      console.log('⚠️  [MIDDLEWARE] Database unavailable, continuing in offline mode');
      req.body.offlineMode = true;
      next();
    } else {
      console.error('❌ Database connection failed:', error);
      res.status(503).json({
        error: 'Database unavailable',
        message: 'Unable to connect to database. Please try again later.',
        details: isDevelopment ? error.message : undefined
      });
    }
  }
}

// Enhanced health check endpoint middleware
export async function healthCheck(req: Request, res: Response) {
  const health = await checkDatabaseHealth();
  
  const responseStatus = health.canContinue ? (health.healthy ? 200 : 206) : 503;
  
  res.status(responseStatus).json({
    status: health.healthy ? 'healthy' : health.canContinue ? 'degraded' : 'unhealthy',
    service: 'TimeTracker Pro',
    database: {
      connected: health.healthy,
      details: health.details,
      mode: health.canContinue && !health.healthy ? 'offline-development' : 'normal'
    },
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
}
