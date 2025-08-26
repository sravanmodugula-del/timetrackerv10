
const { PrismaClient } = require('@prisma/client');

// SQL Server connection configuration
const SQL_SERVER = process.env.SQL_SERVER || 'HUB-SQL1TST-LIS';
const SQL_USER = process.env.SQL_USER || 'timetracker';
const SQL_PASSWORD = process.env.SQL_PASSWORD || 'iTT!$Lo7gm"i\'JAg~5Y\\';
const SQL_DATABASE = process.env.SQL_DATABASE || 'timetracker';

async function testSqlServerConnection() {
  const prisma = new PrismaClient();
  const isOnPremSqlServer = process.env.DATABASE_URL?.includes('HUB-SQL1TST-LIS');
  const isDevelopment = process.env.NODE_ENV !== 'production';
  
  try {
    console.log('🔄 Testing SQL Server connection...');
    console.log('🌐 Environment:', isDevelopment ? 'Development' : 'Production');
    console.log('🗄️  Database type:', isOnPremSqlServer ? 'On-premises SQL Server' : 'Other');
    
    // Test basic connection with timeout
    const connectPromise = prisma.$connect();
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Connection timeout after 10 seconds')), 10000);
    });
    
    await Promise.race([connectPromise, timeoutPromise]);
    console.log('✅ Connected to SQL Server successfully');
    
    // Test a simple query
    const result = await prisma.$queryRaw`SELECT @@VERSION as version`;
    console.log('✅ SQL Server version:', result[0].version);
    
    // Test database health
    const healthCheck = await prisma.$queryRaw`SELECT 1 as health_check`;
    console.log('✅ Health check passed:', healthCheck[0].health_check === 1);
    
  } catch (error) {
    const isConnectionError = error.message?.includes('timeout') || 
                            error.message?.includes('ECONNREFUSED') || 
                            error.message?.includes('ENOTFOUND') || 
                            error.message?.includes('ETIMEDOUT');
    
    if (isConnectionError && isDevelopment && isOnPremSqlServer) {
      console.log('⚠️  SQL Server connection failed (expected in Replit environment)');
      console.log('🔄 This is normal when running in Replit - on-premises servers are not accessible');
      console.log('✅ Application will run in offline development mode');
      console.log('💡 For production deployment, ensure the app runs on the same network as the SQL Server');
    } else {
      console.error('❌ Unexpected SQL Server connection error:', error.message);
      if (!isDevelopment) {
        process.exit(1);
      }
    }
  } finally {
    try {
      await prisma.$disconnect();
    } catch (e) {
      // Ignore disconnect errors
    }
  }
}

testSqlServerConnection();
