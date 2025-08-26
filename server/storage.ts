import { prisma, withDatabaseRetry } from "./db";
import type {
  User,
  Project,
  Task,
  TimeEntry,
  Employee,
  ProjectEmployee,
  Prisma
} from '@prisma/client';

// Enhanced logging utility
function logError(operation: string, error: unknown) {
  console.error(`❌ [STORAGE] ${operation} failed:`, error);
}

function logSuccess(operation: string, details?: any) {
  console.log(`✅ [STORAGE] ${operation} successful`, details ? `- ${JSON.stringify(details)}` : '');
}

// User operations
export async function upsertUser(userData: Prisma.UserCreateInput): Promise<User | null> {
  return withDatabaseRetry(async () => {
    try {
      const user = await prisma.user.upsert({
        where: { email: userData.email },
        update: userData,
        create: userData,
      });
      logSuccess('User upsert', { id: user.id, email: user.email });
      return user;
    } catch (error) {
      logError('User upsert', error);
      throw error;
    }
  }, 3, 'User upsert');
}

export async function getUserById(id: string): Promise<User | null> {
  return withDatabaseRetry(async () => {
    try {
      const user = await prisma.user.findUnique({
        where: { id },
      });
      return user;
    } catch (error) {
      logError('Get user by ID', error);
      throw error;
    }
  }, 3, 'Get user by ID');
}

export async function getUserByEmail(email: string): Promise<User | null> {
  return withDatabaseRetry(async () => {
    try {
      const user = await prisma.user.findUnique({
        where: { email },
      });
      return user;
    } catch (error) {
      logError('Get user by email', error);
      throw error;
    }
  }, 3, 'Get user by email');
}

export async function getAllUsers(): Promise<User[]> {
  const fallbackUsers: User[] = []; // Empty array as fallback

  return withDatabaseRetry(async () => {
    try {
      const users = await prisma.user.findMany({
        orderBy: { createdAt: 'desc' },
      });
      logSuccess('Get all users', { count: users.length });
      return users;
    } catch (error) {
      logError('Get all users', error);
      throw error;
    }
  }, 3, 'Get all users', fallbackUsers);
}

// Project operations
export async function createProject(projectData: any, userId?: string): Promise<PrismaProject> {
  return withDatabaseRetry(async () => {
    try {
      const data = userId ? { ...projectData, userId } : projectData;
      const project = await prisma.project.create({
        data: data,
        include: {
          user: true,
          tasks: true,
          timeEntries: true,
          projectEmployees: {
            include: {
              employee: true,
            },
          },
        },
      });
      logSuccess('Project creation', { id: project.id, name: project.name });
      return project;
    } catch (error) {
      logError('Project creation', error);
      throw error;
    }
  }, 3, 'Project creation');
}

export async function getProjectById(id: string): Promise<PrismaProject | null> {
  return withDatabaseRetry(async () => {
    try {
      const project = await prisma.project.findUnique({
        where: { id },
        include: {
          user: true,
          tasks: true,
          timeEntries: true,
          projectEmployees: {
            include: {
              employee: true,
            },
          },
        },
      });
      return project;
    } catch (error) {
      logError('Get project by ID', error);
      throw error;
    }
  }, 3, 'Get project by ID');
}

export async function getProjectsByUserId(userId: string): Promise<PrismaProject[]> {
  return withDatabaseRetry(async () => {
    try {
      const projects = await prisma.project.findMany({
        where: { userId },
        include: {
          tasks: true,
          timeEntries: true,
        },
        orderBy: { createdAt: 'desc' },
      });
      logSuccess('Get projects by user ID', { userId, count: projects.length });
      return projects;
    } catch (error) {
      logError('Get projects by user ID', error);
      throw error;
    }
  }, 3, 'Get projects by user ID');
}

export async function getAllProjects(): Promise<PrismaProject[]> {
  return withDatabaseRetry(async () => {
    try {
      const projects = await prisma.project.findMany({
        include: {
          user: true,
          tasks: true,
          timeEntries: true,
        },
        orderBy: { createdAt: 'desc' },
      });
      logSuccess('Get all projects', { count: projects.length });
      return projects;
    } catch (error) {
      logError('Get all projects', error);
      throw error;
    }
  }, 3, 'Get all projects');
}

export async function updateProject(id: string, updateData: Prisma.ProjectUpdateInput): Promise<PrismaProject> {
  return withDatabaseRetry(async () => {
    try {
      const project = await prisma.project.update({
        where: { id },
        data: updateData,
      });
      logSuccess('Project update', { id, name: project.name });
      return project;
    } catch (error) {
      logError('Project update', error);
      throw error;
    }
  }, 3, 'Project update');
}

export async function deleteProject(id: string, userId?: string): Promise<boolean> {
  return withDatabaseRetry(async () => {
    try {
      await prisma.project.delete({
        where: { id },
      });
      logSuccess('Project deletion', { id });
      return true;
    } catch (error) {
      logError('Project deletion', error);
      return false;
    }
  }, 3, 'Project deletion');
}

// Task operations
export async function createTask(taskData: any): Promise<PrismaTask> {
  return withDatabaseRetry(async () => {
    try {
      const task = await prisma.task.create({
        data: taskData,
        include: {
          project: true,
          timeEntries: true,
        },
      });
      logSuccess('Task creation', { id: task.id, name: task.name });
      return task;
    } catch (error) {
      logError('Task creation', error);
      throw error;
    }
  }, 3, 'Task creation');
}

export async function getTasksByProjectId(projectId: string): Promise<PrismaTask[]> {
  return withDatabaseRetry(async () => {
    try {
      const tasks = await prisma.task.findMany({
        where: { projectId },
        include: {
          project: true,
          timeEntries: true,
        },
        orderBy: { createdAt: 'desc' },
      });
      return tasks;
    } catch (error) {
      logError('Get tasks by project ID', error);
      throw error;
    }
  }, 3, 'Get tasks by project ID');
}

export async function updateTask(id: string, updateData: any, userId?: string): Promise<PrismaTask | null> {
  return withDatabaseRetry(async () => {
    try {
      const task = await prisma.task.update({
        where: { id },
        data: updateData,
        include: {
          project: true,
          timeEntries: true,
        },
      });
      logSuccess('Task update', { id, name: task.name });
      return task;
    } catch (error) {
      logError('Task update', error);
      throw error;
    }
  }, 3, 'Task update');
}

export async function deleteTask(id: string, userId?: string): Promise<boolean> {
  return withDatabaseRetry(async () => {
    try {
      await prisma.task.delete({
        where: { id },
      });
      logSuccess('Task deletion', { id });
      return true;
    } catch (error) {
      logError('Task deletion', error);
      return false;
    }
  }, 3, 'Task deletion');
}

// Time entry operations
export async function createTimeEntry(timeEntryData: any): Promise<PrismaTimeEntry> {
  return withDatabaseRetry(async () => {
    try {
      const timeEntry = await prisma.timeEntry.create({
        data: timeEntryData,
        include: {
          user: true,
          project: true,
          task: true,
        },
      });
      logSuccess('Time entry creation', { id: timeEntry.id });
      return timeEntry;
    } catch (error) {
      logError('Time entry creation', error);
      throw error;
    }
  }, 3, 'Time entry creation');
}

export async function getTimeEntriesByUserId(userId: string, startDate?: Date, endDate?: Date): Promise<PrismaTimeEntry[]> {
  return withDatabaseRetry(async () => {
    try {
      const whereClause: Prisma.TimeEntryWhereInput = { userId };

      if (startDate && endDate) {
        whereClause.date = {
          gte: startDate,
          lte: endDate,
        };
      }

      const timeEntries = await prisma.timeEntry.findMany({
        where: whereClause,
        include: {
          user: true,
          project: true,
          task: true,
        },
        orderBy: { date: 'desc' },
      });
      return timeEntries;
    } catch (error) {
      logError('Get time entries by user ID', error);
      throw error;
    }
  }, 3, 'Get time entries by user ID');
}

export async function getTimeEntriesByProjectId(projectId: string): Promise<PrismaTimeEntry[]> {
  return withDatabaseRetry(async () => {
    try {
      const timeEntries = await prisma.timeEntry.findMany({
        where: { projectId },
        include: {
          user: true,
          project: true,
          task: true,
        },
        orderBy: { date: 'desc' },
      });
      return timeEntries;
    } catch (error) {
      logError('Get time entries by project ID', error);
      throw error;
    }
  }, 3, 'Get time entries by project ID');
}

export async function updateTimeEntry(id: string, updateData: any, userId?: string): Promise<PrismaTimeEntry | null> {
  return withDatabaseRetry(async () => {
    try {
      if (userId) {
        const result = await prisma.timeEntry.updateMany({
          where: {
            id,
            userId
          },
          data: updateData,
        });

        if (result.count === 0) {
          return null;
        }

        // Return the updated time entry
        const updatedEntry = await prisma.timeEntry.findUnique({
          where: { id },
          include: {
            user: true,
            project: true,
            task: true,
          },
        });

        logSuccess('Time entry update', { id });
        return updatedEntry;
      } else {
        const timeEntry = await prisma.timeEntry.update({
          where: { id },
          data: updateData,
        });
        logSuccess('Time entry update', { id });
        return timeEntry;
      }
    } catch (error) {
      logError('Time entry update', error);
      throw error;
    }
  }, 3, 'Time entry update');
}

export async function deleteTimeEntry(id: string, userId?: string): Promise<boolean> {
  return withDatabaseRetry(async () => {
    try {
      if (userId) {
        const result = await prisma.timeEntry.deleteMany({
          where: {
            id,
            userId
          },
        });

        const deleted = result.count > 0;
        if (deleted) {
          logSuccess('Time entry deletion', { id });
        }
        return deleted;
      } else {
        await prisma.timeEntry.delete({
          where: { id },
        });
        logSuccess('Time entry deletion', { id });
        return true;
      }
    } catch (error) {
      logError('Time entry deletion', error);
      return false;
    }
  }, 3, 'Time entry deletion');
}

// Missing function needed by routes.ts
export async function getTimeEntries(userId: string, filters?: {
  projectId?: string;
  startDate?: string;
  endDate?: string;
  limit?: number;
  offset?: number;
}): Promise<PrismaTimeEntry[]> {
  return withDatabaseRetry(async () => {
    try {
      const whereClause: any = { userId };

      if (filters?.projectId) {
        whereClause.projectId = filters.projectId;
      }

      if (filters?.startDate && filters?.endDate) {
        whereClause.date = {
          gte: new Date(filters.startDate),
          lte: new Date(filters.endDate),
        };
      }

      const timeEntries = await prisma.timeEntry.findMany({
        where: whereClause,
        include: {
          user: true,
          project: true,
          task: true,
        },
        orderBy: { date: 'desc' },
        take: filters?.limit,
        skip: filters?.offset,
      });
      return timeEntries;
    } catch (error) {
      logError('Get time entries', error);
      throw error;
    }
  }, 3, 'Get time entries');
}

// Missing function needed by routes.ts
export async function getTimeEntry(id: string, userId: string): Promise<PrismaTimeEntry | null> {
  return withDatabaseRetry(async () => {
    try {
      const timeEntry = await prisma.timeEntry.findFirst({
        where: {
          id,
          userId
        },
        include: {
          user: true,
          project: true,
          task: true,
        },
      });
      return timeEntry;
    } catch (error) {
      logError('Get time entry by ID', error);
      throw error;
    }
  }, 3, 'Get time entry by ID');
}

// Employee operations
export async function createEmployee(employeeData: any): Promise<PrismaEmployee> {
  return withDatabaseRetry(async () => {
    try {
      const employee = await prisma.employee.create({
        data: employeeData,
        include: {
          user: true,
          department: true,
          projectEmployees: {
            include: {
              project: true,
            },
          },
        },
      });
      logSuccess('Employee creation', { id: employee.id, employeeId: employee.employeeId });
      return employee;
    } catch (error) {
      logError('Employee creation', error);
      throw error;
    }
  }, 3, 'Employee creation');
}

export async function getEmployeesByUserId(userId: string): Promise<PrismaEmployee[]> {
  return withDatabaseRetry(async () => {
    try {
      const employees = await prisma.employee.findMany({
        where: { userId },
        include: {
          user: true,
          projectEmployees: {
            include: {
              project: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      });
      return employees;
    } catch (error) {
      logError('Get employees by user ID', error);
      throw error;
    }
  }, 3, 'Get employees by user ID');
}

export async function getAllEmployees(): Promise<PrismaEmployee[]> {
  return withDatabaseRetry(async () => {
    try {
      const employees = await prisma.employee.findMany({
        include: {
          user: true,
          projectEmployees: {
            include: {
              project: true,
            },
          },
        },
        orderBy: { createdAt: 'desc' },
      });
      logSuccess('Get all employees', { count: employees.length });
      return employees;
    } catch (error) {
      logError('Get all employees', error);
      throw error;
    }
  }, 3, 'Get all employees');
}

export async function updateEmployee(id: string, updateData: any, userId?: string): Promise<PrismaEmployee | null> {
  return withDatabaseRetry(async () => {
    try {
      const employee = await prisma.employee.update({
        where: { id },
        data: updateData,
        include: {
          user: true,
          projectEmployees: {
            include: {
              project: true,
            },
          },
        },
      });
      logSuccess('Employee update', { id, employeeId: employee.employeeId });
      return employee;
    } catch (error) {
      logError('Employee update', error);
      throw error;
    }
  }, 3, 'Employee update');
}

export async function deleteEmployee(id: string, userId?: string): Promise<boolean> {
  return withDatabaseRetry(async () => {
    try {
      await prisma.employee.delete({
        where: { id },
      });
      logSuccess('Employee deletion', { id });
      return true;
    } catch (error) {
      logError('Employee deletion', error);
      return false;
    }
  }, 3, 'Employee deletion');
}

// Project Employee assignment operations
export async function assignEmployeeToProject(assignmentData: Prisma.ProjectEmployeeCreateInput): Promise<PrismaProjectEmployee> {
  return withDatabaseRetry(async () => {
    try {
      const assignment = await prisma.projectEmployee.create({
        data: assignmentData,
      });
      logSuccess('Employee project assignment', { id: assignment.id });
      return assignment;
    } catch (error) {
      logError('Employee project assignment', error);
      throw error;
    }
  }, 3, 'Employee project assignment');
}

export async function removeEmployeeFromProject(projectId: string, employeeId: string, userId?: string): Promise<boolean> {
  return withDatabaseRetry(async () => {
    try {
      const result = await prisma.projectEmployee.deleteMany({
        where: {
          projectId,
          employeeId,
        },
      });

      const removed = result.count > 0;
      if (removed) {
        logSuccess('Employee project removal', { projectId, employeeId });
      }
      return removed;
    } catch (error) {
      logError('Employee project removal', error);
      return false;
    }
  }, 3, 'Employee project removal');
}

export async function getProjectEmployees(projectId: string, userId?: string): Promise<any[]> {
  return withDatabaseRetry(async () => {
    try {
      const assignments = await prisma.projectEmployee.findMany({
        where: { projectId },
        include: {
          project: true,
          employee: {
            include: {
              user: true,
              department: true,
            }
          },
        },
      });
      return assignments;
    } catch (error) {
      logError('Get project employees', error);
      throw error;
    }
  }, 3, 'Get project employees');
}

// Database cleanup on application shutdown
export async function closeDatabase(): Promise<void> {
  try {
    await prisma.$disconnect();
    console.log('✅ [DATABASE] Connection closed successfully');
  } catch (error) {
    console.error('❌ [DATABASE] Error closing connection:', error);
  }
}

// Health check and maintenance
export async function performDatabaseMaintenance(): Promise<void> {
  return withDatabaseRetry(async () => {
    try {
      // Perform basic maintenance queries if needed
      await prisma.$queryRaw`SELECT 1`;
      logSuccess('Database maintenance');
    } catch (error) {
      logError('Database maintenance', error);
      throw error;
    }
  }, 3, 'Database maintenance');
}

// Additional missing functions for routes.ts compatibility

export async function getProjects(): Promise<PrismaProject[]> {
  return getAllProjects();
}

export async function getProject(id: string, userId?: string): Promise<PrismaProject | null> {
  return getProjectById(id);
}

export async function assignEmployeesToProject(projectId: string, employeeIds: string[], userId: string): Promise<void> {
  return withDatabaseRetry(async () => {
    try {
      // Remove existing assignments first
      await prisma.projectEmployee.deleteMany({
        where: { projectId }
      });

      // Add new assignments
      const assignments = employeeIds.map(employeeId => ({
        projectId,
        employeeId,
        userId
      }));

      if (assignments.length > 0) {
        await prisma.projectEmployee.createMany({
          data: assignments
        });
      }

      logSuccess('Employees assigned to project', { projectId, employeeCount: employeeIds.length });
    } catch (error) {
      logError('Assign employees to project', error);
      throw error;
    }
  }, 3, 'Assign employees to project');
}

export async function getTasks(projectId: string, userId: string): Promise<PrismaTask[]> {
  return getTasksByProjectId(projectId);
}

export async function getAllUserTasks(userId: string): Promise<PrismaTask[]> {
  return withDatabaseRetry(async () => {
    try {
      const tasks = await prisma.task.findMany({
        include: {
          project: true,
          timeEntries: true,
        },
        orderBy: { createdAt: 'desc' },
      });
      return tasks;
    } catch (error) {
      logError('Get all user tasks', error);
      throw error;
    }
  }, 3, 'Get all user tasks');
}

export async function getTask(id: string, userId: string): Promise<PrismaTask | null> {
  return withDatabaseRetry(async () => {
    try {
      const task = await prisma.task.findUnique({
        where: { id },
        include: {
          project: true,
          timeEntries: true,
        },
      });
      return task;
    } catch (error) {
      logError('Get task by ID', error);
      throw error;
    }
  }, 3, 'Get task by ID');
}

export async function getDashboardStats(userId: string, startDate?: string, endDate?: string): Promise<any> {
  return withDatabaseRetry(async () => {
    try {
      const user = await getUserById(userId);
      const userRole = user?.role || 'employee';

      let whereConditions: any = {};
      if (userRole !== 'admin') {
        whereConditions.userId = userId;
      }

      if (startDate && endDate) {
        whereConditions.date = {
          gte: new Date(startDate),
          lte: new Date(endDate),
        };
      }

      const timeEntries = await prisma.timeEntry.findMany({
        where: whereConditions,
        include: {
          project: true,
        },
      });

      const totalHours = timeEntries.reduce((sum, entry) => sum + (entry.duration || 0), 0);
      const totalProjects = new Set(timeEntries.map(entry => entry.projectId)).size;
      const totalEntries = timeEntries.length;

      return {
        totalHours,
        totalProjects,
        totalEntries,
        averageHoursPerDay: totalHours / 7, // Simplified calculation
      };
    } catch (error) {
      logError('Get dashboard stats', error);
      throw error;
    }
  }, 3, 'Get dashboard stats');
}

export async function getProjectTimeBreakdown(userId: string, startDate?: string, endDate?: string): Promise<any[]> {
  return withDatabaseRetry(async () => {
    try {
      const user = await getUserById(userId);
      const userRole = user?.role || 'employee';

      let whereConditions: any = {};
      if (userRole !== 'admin') {
        whereConditions.userId = userId;
      }

      if (startDate && endDate) {
        whereConditions.date = {
          gte: new Date(startDate),
          lte: new Date(endDate),
        };
      }

      const timeEntries = await prisma.timeEntry.findMany({
        where: whereConditions,
        include: {
          project: true,
        },
      });

      const breakdown = timeEntries.reduce((acc: any, entry) => {
        const projectName = entry.project?.name || 'Unknown Project';
        if (!acc[projectName]) {
          acc[projectName] = { name: projectName, hours: 0 };
        }
        acc[projectName].hours += entry.duration || 0;
        return acc;
      }, {});

      return Object.values(breakdown);
    } catch (error) {
      logError('Get project time breakdown', error);
      throw error;
    }
  }, 3, 'Get project time breakdown');
}

export async function getRecentActivity(userId: string, limit?: number, startDate?: string, endDate?: string): Promise<any[]> {
  return withDatabaseRetry(async () => {
    try {
      const user = await getUserById(userId);
      const userRole = user?.role || 'employee';

      let whereConditions: any = {};
      if (userRole !== 'admin') {
        whereConditions.userId = userId;
      }

      if (startDate && endDate) {
        whereConditions.date = {
          gte: new Date(startDate),
          lte: new Date(endDate),
        };
      }

      const timeEntries = await prisma.timeEntry.findMany({
        where: whereConditions,
        include: {
          project: true,
          task: true,
        },
        orderBy: { date: 'desc' },
        take: limit || 10,
      });

      return timeEntries.map(entry => ({
        id: entry.id,
        date: entry.date,
        duration: entry.duration,
        description: entry.description,
        project: entry.project?.name,
        task: entry.task?.name,
      }));
    } catch (error) {
      logError('Get recent activity', error);
      throw error;
    }
  }, 3, 'Get recent activity');
}

export async function getDepartmentHoursSummary(userId: string, startDate?: string, endDate?: string): Promise<any[]> {
  return withDatabaseRetry(async () => {
    try {
      const user = await getUserById(userId);
      const userRole = user?.role || 'employee';

      let timeEntriesConditions: any = {};
      if (userRole !== 'admin') {
        timeEntriesConditions.userId = userId;
      }

      if (startDate && endDate) {
        timeEntriesConditions.date = {
          gte: new Date(startDate),
          lte: new Date(endDate),
        };
      }

      const timeEntries = await prisma.timeEntry.findMany({
        where: timeEntriesConditions,
        include: {
          user: {
            include: {
              employees: {
                include: {
                  department: true,
                }
              }
            }
          }
        },
      });

      const departmentHours = timeEntries.reduce((acc: any, entry) => {
        const employee = entry.user?.employees?.[0];
        const departmentName = employee?.department?.name || 'Unassigned';

        if (!acc[departmentName]) {
          acc[departmentName] = { department: departmentName, hours: 0 };
        }
        acc[departmentName].hours += entry.duration || 0;
        return acc;
      }, {});

      return Object.values(departmentHours);
    } catch (error) {
      logError('Get department hours summary', error);
      throw error;
    }
  }, 3, 'Get department hours summary');
}

export async function createTestUsers(): Promise<any[]> {
  return withDatabaseRetry(async () => {
    try {
      const testUsers = [
        { email: 'test.admin@example.com', firstName: 'Test', lastName: 'Admin', role: 'admin' },
        { email: 'test.manager@example.com', firstName: 'Test', lastName: 'Manager', role: 'manager' },
        { email: 'test.pm@example.com', firstName: 'Test', lastName: 'ProjectManager', role: 'project_manager' },
        { email: 'test.employee@example.com', firstName: 'Test', lastName: 'Employee', role: 'employee' },
      ];

      const createdUsers = [];
      for (const userData of testUsers) {
        const user = await upsertUser(userData);
        if (user) createdUsers.push(user);
      }

      logSuccess('Test users created', { count: createdUsers.length });
      return createdUsers;
    } catch (error) {
      logError('Create test users', error);
      throw error;
    }
  }, 3, 'Create test users');
}

export async function getTestUsers(): Promise<PrismaUser[]> {
  return withDatabaseRetry(async () => {
    try {
      const testUsers = await prisma.user.findMany({
        where: {
          email: {
            startsWith: 'test.'
          }
        },
        orderBy: { createdAt: 'desc' },
      });
      return testUsers;
    } catch (error) {
      logError('Get test users', error);
      throw error;
    }
  }, 3, 'Get test users');
}

export async function getTimeEntriesForProject(projectId: string): Promise<any[]> {
  return withDatabaseRetry(async () => {
    try {
      const timeEntries = await prisma.timeEntry.findMany({
        where: { projectId },
        include: {
          user: {
            include: {
              employees: true
            }
          },
          project: true,
          task: true,
        },
        orderBy: { date: 'desc' },
      });

      return timeEntries.map(entry => ({
        ...entry,
        employee: entry.user?.employees?.[0] || null
      }));
    } catch (error) {
      logError('Get time entries for project', error);
      throw error;
    }
  }, 3, 'Get time entries for project');
}

export async function getEmployees(userId: string): Promise<PrismaEmployee[]> {
  return getEmployeesByUserId(userId);
}

export async function getEmployee(id: string, userId: string): Promise<PrismaEmployee | null> {
  return withDatabaseRetry(async () => {
    try {
      const employee = await prisma.employee.findUnique({
        where: { id },
        include: {
          user: true,
          department: true,
          projectEmployees: {
            include: {
              project: true,
            },
          },
        },
      });
      return employee;
    } catch (error) {
      logError('Get employee by ID', error);
      throw error;
    }
  }, 3, 'Get employee by ID');
}

export async function getDepartments(): Promise<any[]> {
  return withDatabaseRetry(async () => {
    try {
      const departments = await prisma.$queryRaw`
        SELECT
          d.id,
          d.name,
          d.description,
          d."organizationId",
          d."managerId",
          d."createdAt",
          d."updatedAt",
          COUNT(e.id)::int as "employeeCount"
        FROM "Department" d
        LEFT JOIN "Employee" e ON d.id = e."departmentId"
        GROUP BY d.id, d.name, d.description, d."organizationId", d."managerId", d."createdAt", d."updatedAt"
        ORDER BY d.name
      `;

      logSuccess('Get departments', { count: (departments as any[]).length });
      return departments as any[];
    } catch (error) {
      logError('Get departments', error);
      throw error;
    }
  }, 3, 'Get departments');
}

export async function getDepartment(id: string): Promise<any | null> {
  return withDatabaseRetry(async () => {
    try {
      const department = await prisma.department.findUnique({
        where: { id },
        include: {
          organization: true,
          manager: true,
          employees: {
            include: {
              user: true
            }
          }
        },
      });
      return department;
    } catch (error) {
      logError('Get department by ID', error);
      throw error;
    }
  }, 3, 'Get department by ID');
}

export async function createDepartment(departmentData: any): Promise<any> {
  return withDatabaseRetry(async () => {
    try {
      const department = await prisma.department.create({
        data: departmentData,
      });
      logSuccess('Department creation', { id: department.id, name: department.name });
      return department;
    } catch (error) {
      logError('Department creation', error);
      throw error;
    }
  }, 3, 'Department creation');
}

export async function updateDepartment(id: string, updateData: any, userId: string): Promise<any> {
  return withDatabaseRetry(async () => {
    try {
      const department = await prisma.department.update({
        where: { id },
        data: updateData,
      });
      logSuccess('Department update', { id, name: department.name });
      return department;
    } catch (error) {
      logError('Department update', error);
      throw error;
    }
  }, 3, 'Department update');
}

export async function deleteDepartment(id: string, userId: string): Promise<boolean> {
  return withDatabaseRetry(async () => {
    try {
      await prisma.department.delete({
        where: { id },
      });
      logSuccess('Department deletion', { id });
      return true;
    } catch (error) {
      logError('Department deletion', error);
      return false;
    }
  }, 3, 'Department deletion');
}

export async function assignManagerToDepartment(departmentId: string, managerId: string, userId: string): Promise<void> {
  return withDatabaseRetry(async () => {
    try {
      await prisma.department.update({
        where: { id: departmentId },
        data: { managerId },
      });
      logSuccess('Manager assigned to department', { departmentId, managerId });
    } catch (error) {
      logError('Assign manager to department', error);
      throw error;
    }
  }, 3, 'Assign manager to department');
}

export async function getUsersWithoutEmployeeProfile(): Promise<PrismaUser[]> {
  return withDatabaseRetry(async () => {
    try {
      const users = await prisma.user.findMany({
        where: {
          employees: {
            none: {}
          }
        },
        orderBy: { createdAt: 'desc' },
      });
      return users;
    } catch (error) {
      logError('Get users without employee profile', error);
      throw error;
    }
  }, 3, 'Get users without employee profile');
}

export async function linkUserToEmployee(userId: string, employeeId: string): Promise<Employee | null> {
  return withDatabaseRetry(async () => {
    try {
      const employee = await prisma.employee.update({
        where: { id: employeeId },
        data: { userId },
      });
      logSuccess('User linked to employee', { userId, employeeId });
      return employee;
    } catch (error) {
      logError('Link user to employee', error);
      throw error;
    }
  }, 3, 'Link user to employee');
}

export async function getOrganizations(): Promise<any[]> {
  return withDatabaseRetry(async () => {
    try {
      const organizations = await prisma.organization.findMany({
        orderBy: { createdAt: 'desc' },
      });
      return organizations;
    } catch (error) {
      logError('Get organizations', error);
      throw error;
    }
  }, 3, 'Get organizations');
}

export async function getOrganization(id: string): Promise<any | null> {
  return withDatabaseRetry(async () => {
    try {
      const organization = await prisma.organization.findUnique({
        where: { id },
        include: {
          departments: true,
        },
      });
      return organization;
    } catch (error) {
      logError('Get organization by ID', error);
      throw error;
    }
  }, 3, 'Get organization by ID');
}

export async function createOrganization(organizationData: any): Promise<any> {
  return withDatabaseRetry(async () => {
    try {
      const organization = await prisma.organization.create({
        data: organizationData,
      });
      logSuccess('Organization creation', { id: organization.id, name: organization.name });
      return organization;
    } catch (error) {
      logError('Organization creation', error);
      throw error;
    }
  }, 3, 'Organization creation');
}

export async function updateOrganization(id: string, updateData: any, userId: string): Promise<any> {
  return withDatabaseRetry(async () => {
    try {
      const organization = await prisma.organization.update({
        where: { id },
        data: updateData,
      });
      logSuccess('Organization update', { id, name: organization.name });
      return organization;
    } catch (error) {
      logError('Organization update', error);
      throw error;
    }
  }, 3, 'Organization update');
}

export async function deleteOrganization(id: string, userId: string): Promise<boolean> {
  return withDatabaseRetry(async () => {
    try {
      await prisma.organization.delete({
        where: { id },
      });
      logSuccess('Organization deletion', { id });
      return true;
    } catch (error) {
      logError('Organization deletion', error);
      return false;
    }
  }, 3, 'Organization deletion');
}

export async function getDepartmentsByOrganization(organizationId: string): Promise<any[]> {
  return withDatabaseRetry(async () => {
    try {
      const departments = await prisma.department.findMany({
        where: { organizationId },
        include: {
          employees: true,
        },
        orderBy: { name: 'asc' },
      });
      return departments;
    } catch (error) {
      logError('Get departments by organization', error);
      throw error;
    }
  }, 3, 'Get departments by organization');
}

export async function updateUserRole(userId: string, role: string): Promise<PrismaUser | null> {
  return withDatabaseRetry(async () => {
    try {
      const user = await prisma.user.update({
        where: { id: userId },
        data: { role },
      });
      logSuccess('User role update', { userId, role });
      return user;
    } catch (error) {
      logError('User role update', error);
      throw error;
    }
  }, 3, 'User role update');
}