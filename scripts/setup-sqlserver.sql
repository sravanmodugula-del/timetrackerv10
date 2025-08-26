
-- TimeTracker SQL Server Database Setup
-- Run this script on HUB-SQL1TST-LIS SQL Server instance
-- Execute as sysadmin or database administrator

USE master;
GO

-- Create TimeTracker database with proper configuration
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'timetracker')
BEGIN
    CREATE DATABASE timetracker
    ON (NAME = 'timetracker_data',
        FILENAME = 'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\timetracker.mdf',
        SIZE = 500MB,
        MAXSIZE = 50GB,
        FILEGROWTH = 50MB)
    LOG ON (NAME = 'timetracker_log',
            FILENAME = 'C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\DATA\timetracker_log.ldf',
            SIZE = 50MB,
            MAXSIZE = 5GB,
            FILEGROWTH = 10%);
    
    PRINT 'Database ''timetracker'' created successfully on HUB-SQL1TST-LIS';
END
ELSE
BEGIN
    PRINT 'Database ''timetracker'' already exists on HUB-SQL1TST-LIS';
END
GO

-- Switch to the timetracker database
USE timetracker;
GO

-- Create application login and user with secure credentials
IF NOT EXISTS (SELECT name FROM sys.server_principals WHERE name = 'timetracker')
BEGIN
    CREATE LOGIN timetracker WITH PASSWORD = 'iTT!$Lo7gm"i''JAg~5Y\', 
        DEFAULT_DATABASE = timetracker,
        CHECK_EXPIRATION = OFF,
        CHECK_POLICY = ON;
    PRINT 'Login ''timetracker'' created successfully';
END
ELSE
BEGIN
    PRINT 'Login ''timetracker'' already exists';
END
GO

-- Create database user and assign permissions
IF NOT EXISTS (SELECT name FROM sys.database_principals WHERE name = 'timetracker')
BEGIN
    CREATE USER timetracker FOR LOGIN timetracker;
    
    -- Grant necessary permissions for TimeTracker Pro
    ALTER ROLE db_datareader ADD MEMBER timetracker;
    ALTER ROLE db_datawriter ADD MEMBER timetracker;
    ALTER ROLE db_ddladmin ADD MEMBER timetracker;
    
    -- Additional permissions for schema management
    GRANT CREATE TABLE TO timetracker;
    GRANT CREATE VIEW TO timetracker;
    GRANT CREATE PROCEDURE TO timetracker;
    
    PRINT 'User ''timetracker'' created and permissions granted';
END
ELSE
BEGIN
    PRINT 'User ''timetracker'' already exists';
END
GO

-- Drop existing tables if they exist (in reverse dependency order)
-- First drop all foreign key constraints to avoid dependency issues
DECLARE @sql NVARCHAR(MAX) = '';
SELECT @sql = @sql + 'ALTER TABLE ' + QUOTENAME(s.name) + '.' + QUOTENAME(t.name) + ' DROP CONSTRAINT ' + QUOTENAME(f.name) + ';' + CHAR(13)
FROM sys.foreign_keys f
INNER JOIN sys.tables t ON f.parent_object_id = t.object_id
INNER JOIN sys.schemas s ON t.schema_id = s.schema_id
WHERE s.name = 'dbo';
EXEC sp_executesql @sql;

-- Now drop tables
IF OBJECT_ID('project_employees', 'U') IS NOT NULL DROP TABLE project_employees;
IF OBJECT_ID('time_entries', 'U') IS NOT NULL DROP TABLE time_entries;
IF OBJECT_ID('tasks', 'U') IS NOT NULL DROP TABLE tasks;
IF OBJECT_ID('projects', 'U') IS NOT NULL DROP TABLE projects;
IF OBJECT_ID('departments', 'U') IS NOT NULL DROP TABLE departments;
IF OBJECT_ID('employees', 'U') IS NOT NULL DROP TABLE employees;
IF OBJECT_ID('organizations', 'U') IS NOT NULL DROP TABLE organizations;
IF OBJECT_ID('sessions', 'U') IS NOT NULL DROP TABLE sessions;
IF OBJECT_ID('users', 'U') IS NOT NULL DROP TABLE users;

-- Users table (matches Prisma schema exactly)
CREATE TABLE users (
    id NVARCHAR(255) CONSTRAINT PK_Users PRIMARY KEY,
    email NVARCHAR(255) UNIQUE,
    first_name NVARCHAR(255),
    last_name NVARCHAR(255),
    profile_image_url NVARCHAR(500),
    role NVARCHAR(50) NOT NULL DEFAULT 'employee',
    is_active BIT NOT NULL DEFAULT 1,
    last_login_at DATETIME2,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    updated_at DATETIME2 NOT NULL DEFAULT GETDATE()
);

-- Sessions table for authentication
CREATE TABLE sessions (
    sid NVARCHAR(255) CONSTRAINT PK_Sessions PRIMARY KEY,
    sess NVARCHAR(MAX) NOT NULL,
    expire DATETIME2 NOT NULL
);

-- Create index on expire column
CREATE INDEX IDX_session_expire ON sessions(expire);

-- Organizations table
CREATE TABLE organizations (
    id NVARCHAR(255) CONSTRAINT PK_Organizations PRIMARY KEY DEFAULT NEWID(),
    name NVARCHAR(255) NOT NULL,
    description NTEXT,
    user_id NVARCHAR(255) NOT NULL,
    created_at DATETIME2 DEFAULT GETDATE(),
    updated_at DATETIME2 DEFAULT GETDATE(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Employees table
CREATE TABLE employees (
    id NVARCHAR(255) CONSTRAINT PK_Employees PRIMARY KEY DEFAULT NEWID(),
    employee_id NVARCHAR(255) NOT NULL UNIQUE,
    first_name NVARCHAR(255) NOT NULL,
    last_name NVARCHAR(255) NOT NULL,
    email NVARCHAR(255),
    phone NVARCHAR(50),
    department NVARCHAR(255) NOT NULL,
    position NVARCHAR(255),
    manager_id NVARCHAR(255),
    hire_date DATETIME2,
    salary DECIMAL(10,2),
    is_active BIT NOT NULL DEFAULT 1,
    employment_type NVARCHAR(50) DEFAULT 'full-time',
    user_id NVARCHAR(255) NOT NULL,
    created_at DATETIME2 DEFAULT GETDATE(),
    updated_at DATETIME2 DEFAULT GETDATE(),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (manager_id) REFERENCES employees(id)
);

-- Departments table
CREATE TABLE departments (
    id NVARCHAR(255) CONSTRAINT PK_Departments PRIMARY KEY DEFAULT NEWID(),
    name NVARCHAR(255) NOT NULL,
    organization_id NVARCHAR(255) NOT NULL,
    manager_id NVARCHAR(255),
    description NVARCHAR(500),
    user_id NVARCHAR(255) NOT NULL,
    created_at DATETIME2 DEFAULT GETDATE(),
    updated_at DATETIME2 DEFAULT GETDATE(),
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (manager_id) REFERENCES employees(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Projects table
CREATE TABLE projects (
    id NVARCHAR(255) CONSTRAINT PK_Projects PRIMARY KEY,
    name NVARCHAR(255) NOT NULL,
    project_number NVARCHAR(50),
    description NTEXT,
    color NVARCHAR(7) NOT NULL DEFAULT '#1976D2',
    start_date DATETIME2,
    end_date DATETIME2,
    is_enterprise_wide BIT NOT NULL DEFAULT 1,
    user_id NVARCHAR(255) NOT NULL,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    updated_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tasks table
CREATE TABLE tasks (
    id NVARCHAR(255) CONSTRAINT PK_Tasks PRIMARY KEY,
    project_id NVARCHAR(255) NOT NULL,
    name NVARCHAR(255) NOT NULL,
    description NTEXT,
    status NVARCHAR(50) NOT NULL DEFAULT 'active',
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    updated_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

-- Time entries table
CREATE TABLE time_entries (
    id NVARCHAR(255) CONSTRAINT PK_TimeEntries PRIMARY KEY,
    user_id NVARCHAR(255) NOT NULL,
    project_id NVARCHAR(255) NOT NULL,
    task_id NVARCHAR(255),
    description NTEXT,
    date DATETIME2 NOT NULL,
    start_time NVARCHAR(5) NOT NULL,
    end_time NVARCHAR(5) NOT NULL,
    duration DECIMAL(5,2) NOT NULL,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    updated_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (project_id) REFERENCES projects(id),
    FOREIGN KEY (task_id) REFERENCES tasks(id)
);

-- Project employees table
CREATE TABLE project_employees (
    id NVARCHAR(255) CONSTRAINT PK_ProjectEmployees PRIMARY KEY,
    project_id NVARCHAR(255) NOT NULL,
    employee_id NVARCHAR(255) NOT NULL,
    user_id NVARCHAR(255) NOT NULL,
    created_at DATETIME2 NOT NULL DEFAULT GETDATE(),
    FOREIGN KEY (project_id) REFERENCES projects(id),
    FOREIGN KEY (employee_id) REFERENCES employees(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create indexes for better performance
CREATE INDEX IX_users_email ON users(email);
CREATE INDEX IX_users_role ON users(role);
CREATE INDEX IX_time_entries_user_id ON time_entries(user_id);
CREATE INDEX IX_time_entries_date ON time_entries(date);
CREATE INDEX IX_time_entries_project_id ON time_entries(project_id);
CREATE INDEX IX_tasks_project_id ON tasks(project_id);
CREATE INDEX IX_employees_user_id ON employees(user_id);
CREATE INDEX IX_employees_manager_id ON employees(manager_id);
CREATE INDEX IX_employees_department ON employees(department);
CREATE INDEX IX_employees_email ON employees(email);
CREATE INDEX IX_project_employees_project_id ON project_employees(project_id);
CREATE INDEX IX_project_employees_employee_id ON project_employees(employee_id);

-- Configure database settings for optimal performance
ALTER DATABASE timetracker SET RECOVERY FULL;
ALTER DATABASE timetracker SET AUTO_CLOSE OFF;
ALTER DATABASE timetracker SET AUTO_SHRINK OFF;
ALTER DATABASE timetracker SET AUTO_CREATE_STATISTICS ON;
ALTER DATABASE timetracker SET AUTO_UPDATE_STATISTICS ON;

PRINT 'TimeTracker database setup completed successfully!';
