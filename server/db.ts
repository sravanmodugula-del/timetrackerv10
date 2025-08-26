import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

// Enhanced database configuration for Windows SQL Server
const prismaOptions = process.env.NODE_ENV === 'production' ? {
  log: ['error', 'warn'],
  errorFormat: 'minimal' as const,
} : {
  log: ['query', 'info', 'warn', 'error'],
  errorFormat: 'pretty' as const,
};

export const prisma = globalForPrisma.prisma ?? new PrismaClient(prismaOptions);

// Connection test for Windows SQL Server
if (process.env.NODE_ENV === 'production') {
  prisma.$connect().then(() => {
    console.log('✅ Database connection established to HUB-SQL1TST-LIS');
  }).catch((error) => {
    console.error('❌ Database connection failed:', error);
    console.error('Please verify:');
    console.error('1. SQL Server is running on HUB-SQL1TST-LIS');
    console.error('2. Database credentials are correct');
    console.error('3. Network connectivity is available');
    console.error('4. SQL Server is accepting TCP/IP connections');
  });
}

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;

// Check if we're in a development environment with potentially unreachable SQL Server
const isDevelopment = process.env.NODE_ENV !== 'production';
const isOnPremSqlServer = process.env.DATABASE_URL?.includes('HUB-SQL1TST-LIS');

// Ensure DATABASE_URL is set
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL environment variable is required');
  process.exit(1);
}

console.log('🔗 [DATABASE] Initializing database connection...');
if (isOnPremSqlServer && isDevelopment) {
  console.log('⚠️  [DATABASE] On-premises SQL Server detected in development environment');
  console.log('🔄 [DATABASE] Connection errors will be handled gracefully');
}

// Prisma client instance with enhanced error handling
// const prisma = new PrismaClient({
//   datasources: {
//     db: {
//       url: process.env.DATABASE_URL,
//     },
//   },
//   log: process.env.NODE_ENV === 'development' ? ['error', 'warn'] : ['error'],
//   errorFormat: 'pretty',
// });

// Enhanced database health check with timeout and graceful failure
export async function checkDatabaseHealth(): Promise<{ healthy: boolean; details: string; canContinue: boolean }> {
  try {
    console.log('🔍 [DATABASE] Performing health check...');

    // Set a timeout for the connection attempt
    const healthCheckPromise = prisma.$queryRaw`SELECT 1 as health_check`;
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Database connection timeout')), 10000); // 10 second timeout
    });

    await Promise.race([healthCheckPromise, timeoutPromise]);
    console.log('✅ [DATABASE] Health check passed');
    return { healthy: true, details: 'Connected successfully', canContinue: true };
  } catch (error: any) {
    const isConnectionError = error.message?.includes('timeout') ||
                            error.message?.includes('ECONNREFUSED') ||
                            error.message?.includes('ENOTFOUND') ||
                            error.message?.includes('ETIMEDOUT') ||
                            error.code === 'ECONNREFUSED' ||
                            error.code === 'ENOTFOUND' ||
                            error.code === 'ETIMEDOUT';

    if (isConnectionError && isDevelopment && isOnPremSqlServer) {
      console.log('⚠️  [DATABASE] On-premises SQL Server connection failed (expected in Replit environment)');
      console.log('🔄 [DATABASE] Application will continue in offline mode for development');
      return {
        healthy: false,
        details: 'On-premises SQL Server unreachable (development mode)',
        canContinue: true
      };
    } else {
      console.error('🔴 [DATABASE] Health check failed:', error.message);
      return {
        healthy: false,
        details: error.message,
        canContinue: false
      };
    }
  }
}

// Enhanced database operation wrapper with timeout and graceful fallback
export async function withDatabaseRetry<T>(
  operation: () => Promise<T>,
  maxRetries: number = 3,
  operationName: string = 'Database operation',
  fallbackValue?: T
): Promise<T | null> {
  let lastError: Error;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      // Add timeout to each operation
      const operationPromise = operation();
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error(`${operationName} timeout`)), 15000); // 15 second timeout
      });

      return await Promise.race([operationPromise, timeoutPromise]);
    } catch (error: any) {
      lastError = error as Error;

      const isConnectionError = error.message?.includes('timeout') ||
                              error.message?.includes('ECONNREFUSED') ||
                              error.message?.includes('ENOTFOUND') ||
                              error.message?.includes('ETIMEDOUT') ||
                              error.code === 'ECONNREFUSED' ||
                              error.code === 'ENOTFOUND' ||
                              error.code === 'ETIMEDOUT';

      if (isConnectionError && isDevelopment && isOnPremSqlServer) {
        console.log(`⚠️  [DATABASE] ${operationName} failed due to unreachable on-premises server`);
        if (fallbackValue !== undefined) {
          console.log('🔄 [DATABASE] Using fallback value for development');
          return fallbackValue;
        }
        return null;
      }

      console.warn(`⚠️ ${operationName} failed (attempt ${attempt}/${maxRetries}):`, error.message);

      if (attempt < maxRetries) {
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
        console.log(`🔄 Retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  // If we've exhausted retries and it's a connection error in development, return fallback
  if (isDevelopment && isOnPremSqlServer && fallbackValue !== undefined) {
    console.log('🔄 [DATABASE] All retries exhausted, using fallback value');
    return fallbackValue;
  }

  console.error(`❌ [DATABASE] ${operationName} failed after ${maxRetries} attempts`);
  return null;
}

// Safe database operation wrapper that won't crash the app
export async function safeDatabaseOperation<T>(
  operation: () => Promise<T>,
  operationName: string = 'Database operation',
  fallbackValue: T | null = null
): Promise<T | null> {
  try {
    return await withDatabaseRetry(operation, 2, operationName, fallbackValue);
  } catch (error) {
    console.error(`🔴 [DATABASE] Safe operation failed: ${operationName}`, error);
    return fallbackValue;
  }
}

// Export as 'db' for compatibility with existing imports
export const db = prisma;

// Default export
export default prisma;

// Ensure types are properly exported
export type { PrismaClient } from '@prisma/client';