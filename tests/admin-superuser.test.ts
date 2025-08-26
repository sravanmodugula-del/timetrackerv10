import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { db } from '../server/db.js';
import { users, timeEntries, projects, employees } from '../shared/schema.js';
import { eq } from 'drizzle-orm';
import { storage } from '../server/storage.js';

describe('Admin Superuser Access', () => {
  const adminUserId = 'admin-test-user';
  const regularUserId = 'regular-test-user';
  
  beforeEach(async () => {
    // Clean up test data
    await db.delete(timeEntries);
    await db.delete(employees);  
    await db.delete(projects);
    await db.delete(users);

    // Create admin user
    await storage.upsertUser(adminUserId, 'admin@test.com', 'Admin User');
    await storage.updateUserRole(adminUserId, 'admin');

    // Create regular user  
    await storage.upsertUser(regularUserId, 'user@test.com', 'Regular User');
    await storage.updateUserRole(regularUserId, 'employee');

    // Create test projects for different users
    await db.insert(projects).values([
      {
        id: 'admin-project-1',
        name: 'Admin Project 1',
        projectNumber: 'AP001',
        description: 'Admin owned project',
        userId: adminUserId,
        createdAt: new Date(),
        updatedAt: new Date()
      },
      {
        id: 'user-project-1', 
        name: 'User Project 1',
        projectNumber: 'UP001',
        description: 'User owned project',
        userId: regularUserId,
        createdAt: new Date(),
        updatedAt: new Date()
      }
    ]);

    // Create test time entries for different users
    await db.insert(timeEntries).values([
      {
        id: 'admin-entry-1',
        userId: adminUserId,
        projectId: 'admin-project-1',
        description: 'Admin work',
        date: '2025-08-16',
        startTime: '09:00',
        endTime: '12:00', 
        duration: '3.00',
        createdAt: new Date(),
        updatedAt: new Date()
      },
      {
        id: 'user-entry-1',
        userId: regularUserId,
        projectId: 'user-project-1',
        description: 'User work',
        date: '2025-08-16',
        startTime: '13:00',
        endTime: '17:00',
        duration: '4.00', 
        createdAt: new Date(),
        updatedAt: new Date()
      }
    ]);

    // Create test employees for different users
    await storage.createEmployee({
      firstName: 'Admin',
      lastName: 'Employee', 
      email: 'admin.employee@test.com',
      department: 'Administration',
      userId: adminUserId
    });

    await storage.createEmployee({
      firstName: 'User',
      lastName: 'Employee',
      email: 'user.employee@test.com', 
      department: 'Engineering',
      userId: regularUserId
    });
  });

  afterEach(async () => {
    // Clean up test data
    await db.delete(timeEntries);
    await db.delete(employees);
    await db.delete(projects); 
    await db.delete(users);
  });

  describe('Admin Time Entry Access', () => {
    it('should allow admin to view ALL time entries from all users', async () => {
      const adminEntries = await storage.getTimeEntries(adminUserId);
      
      // Admin should see entries from all users, not just their own
      expect(adminEntries.length).toBe(2);
      expect(adminEntries.some((entry: any) => entry.userId === adminUserId)).toBe(true);
      expect(adminEntries.some((entry: any) => entry.userId === regularUserId)).toBe(true);
    });

    it('should allow admin to edit any time entry from any user', async () => {
      const updatedEntry = await storage.updateTimeEntry('user-entry-1', {
        description: 'Modified by admin',
        duration: '5.00'
      }, adminUserId);

      expect(updatedEntry?.description).toBe('Modified by admin'); 
      expect(updatedEntry?.duration).toBe('5.00');
    });

    it('should allow admin to delete any time entry from any user', async () => {
      const deleted = await storage.deleteTimeEntry('user-entry-1', adminUserId);
      expect(deleted).toBe(true);

      // Verify entry was deleted
      const entry = await storage.getTimeEntry('user-entry-1', adminUserId);
      expect(entry).toBeUndefined();
    });
  });

  describe('Admin Employee Access', () => {
    it('should allow admin to view ALL employees from all users', async () => {
      const allEmployees = await storage.getEmployees(adminUserId);

      expect(allEmployees.length).toBe(2);
      expect(allEmployees.some((emp: any) => emp.userId === adminUserId)).toBe(true);
      expect(allEmployees.some((emp: any) => emp.userId === regularUserId)).toBe(true);
    });

    it('should allow admin to edit any employee from any user', async () => {
      const response = await request(app)
        .put(`/api/employees/user-employee-1`)
        .send({
          firstName: 'Modified',
          lastName: 'ByAdmin'
        })
        .expect(200);

      expect(response.body.firstName).toBe('Modified');
      expect(response.body.lastName).toBe('ByAdmin');
    });

    it('should allow admin to delete any employee from any user', async () => {
      await request(app)
        .delete(`/api/employees/user-employee-1`)
        .expect(204);

      // Verify employee was deleted  
      const employeeList = await db.select().from(employees).where(eq(employees.id, 'user-employee-1'));
      expect(employeeList).toHaveLength(0);
    });
  });

  describe('Admin Dashboard Access', () => {
    it('should show admin company-wide dashboard statistics', async () => {
      const stats = await storage.getDashboardStats(adminUserId);

      // Admin should see combined hours from all users (3.00 + 4.00 = 7.00)
      expect(stats.todayHours).toBeGreaterThan(6);
      expect(stats.activeProjects).toBe(2); // All projects visible
    });

    it('should show admin project breakdown from all users', async () => {
      const breakdown = await storage.getProjectTimeBreakdown(adminUserId);

      expect(breakdown.length).toBe(2);
      expect(breakdown.some((p: any) => p.project.userId === adminUserId)).toBe(true);
      expect(breakdown.some((p: any) => p.project.userId === regularUserId)).toBe(true);
    });

    it('should show admin department breakdown from all users', async () => {
      const deptBreakdown = await storage.getDepartmentHoursSummary(adminUserId, '2025-08-01', '2025-08-31');

      expect(deptBreakdown.length).toBeGreaterThan(0);
      expect(deptBreakdown.some((d: any) => d.departmentName === 'Administration')).toBe(true);
      expect(deptBreakdown.some((d: any) => d.departmentName === 'Engineering')).toBe(true);
    });
  });

  describe('Regular User Access Restrictions', () => {
    it('should restrict regular user to only their own time entries', async () => {
      const userEntries = await storage.getTimeEntries(regularUserId);

      expect(userEntries.length).toBe(1);
      expect(userEntries[0].userId).toBe(regularUserId);
    });

    it('should restrict regular user to only their own employees', async () => {
      const userEmployees = await storage.getEmployees(regularUserId);

      expect(userEmployees.length).toBe(1);
      expect(userEmployees[0].userId).toBe(regularUserId);
    });

    it('should show regular user only personal dashboard statistics', async () => {
      const userStats = await storage.getDashboardStats(regularUserId);

      // Regular user should see only their hours (4.00)
      expect(userStats.todayHours).toBe(4);
      expect(userStats.activeProjects).toBe(1); // Only their projects
    });
  });

  describe('Admin CRUD Operations', () => {
    it('should allow admin to create time entries in any project', async () => {
      // Admin can create time entries in any project
      const newEntry = await storage.createTimeEntry({
        userId: adminUserId,
        projectId: 'user-project-1', // User's project, but admin can create entry
        description: 'Admin creating entry in user project',
        date: '2025-08-17',
        startTime: '09:00',
        endTime: '11:00',
        duration: '2.00'
      });

      expect(newEntry.description).toBe('Admin creating entry in user project');
      expect(newEntry.projectId).toBe('user-project-1');
    });

    it('should allow admin to view individual records from any user', async () => {
      // Admin can view user's specific time entry
      const entry = await storage.getTimeEntry('user-entry-1', adminUserId);

      expect(entry?.id).toBe('user-entry-1');
      expect(entry?.userId).toBe(regularUserId);
    });

    it('should allow admin to access any user data regardless of ownership', async () => {
      // Test admin can access regular user's data
      const regularUserEntries = await storage.getTimeEntries(adminUserId);
      const regularUserEmployees = await storage.getEmployees(adminUserId);

      // Admin should see data from all users
      expect(regularUserEntries.length).toBeGreaterThan(1);
      expect(regularUserEmployees.length).toBeGreaterThan(1);
    });
  });
});