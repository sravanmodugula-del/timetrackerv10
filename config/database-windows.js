// Windows SQL Server Database Configuration for TimeTracker

const sql = require('mssql');

const config = {
  server: process.env.SQL_SERVER || 'HUB-SQL1TST-LIS',
  database: 'timetracker',
  user: process.env.SQL_USER || 'timetracker',
  password: process.env.SQL_PASSWORD || 'iTT!$Lo7gm"i\'JAg~5Y\\',
  options: {
    encrypt: true,
    trustServerCertificate: true,
    enableArithAbort: true
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

module.exports = { sql, config };

const dbConfig = {
    user: process.env.SQL_USER || 'timetracker',
    password: process.env.SQL_PASSWORD || 'iTT!$Lo7gm"i\'JAg~5Y\\',
    server: process.env.SQL_SERVER || 'HUB-SQL1TST-LIS',
    database: process.env.SQL_DATABASE || 'timetracker',
    port: parseInt(process.env.DB_PORT) || 1433,
    options: {
        encrypt: process.env.DB_ENCRYPT === 'true' || false, // Use true for Azure SQL
        trustServerCertificate: process.env.DB_TRUST_CERT === 'true' || true,
        enableArithAbort: true,
        connectionTimeout: 30000,
        requestTimeout: 30000,
    },
    pool: {
        max: 20,
        min: 0,
        idleTimeoutMillis: 30000,
    },
};

class DatabaseManager {
    constructor() {
        this.pool = null;
    }

    async connect() {
        try {
            this.pool = await sql.connect(dbConfig);
            console.log('✅ Connected to SQL Server database');
            return this.pool;
        } catch (error) {
            console.error('❌ Database connection failed:', error);
            throw error;
        }
    }

    async disconnect() {
        try {
            if (this.pool) {
                await this.pool.close();
                console.log('✅ Database connection closed');
            }
        } catch (error) {
            console.error('❌ Error closing database connection:', error);
        }
    }

    getPool() {
        return this.pool;
    }
}

module.exports = new DatabaseManager();