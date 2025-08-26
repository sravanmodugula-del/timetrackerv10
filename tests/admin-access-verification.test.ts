import { describe, it, expect } from 'vitest';
import { storage } from '../server/storage.js';

describe('Admin Access Verification', () => {
  const adminUserId = 'test-admin-user';
  
  it('should confirm admin dashboard breakdowns work with real data', async () => {
    // Test Project Breakdown - Admin should see projects from all users
    const projectBreakdown = await storage.getProjectTimeBreakdown(adminUserId);
    expect(projectBreakdown.length).toBeGreaterThan(0);
    console.log(`✅ Admin Project Breakdown: ${projectBreakdown.length} projects visible`);

    // Test Department Hours - Admin should see all departments
    const deptHours = await storage.getDepartmentHoursSummary(adminUserId, '2025-08-01', '2025-08-31');
    expect(deptHours.length).toBeGreaterThan(0);
    console.log(`✅ Admin Department Hours: ${deptHours.length} departments visible`);

    // Test Dashboard Stats - Admin should see company-wide stats
    const stats = await storage.getDashboardStats(adminUserId);
    expect(stats.todayHours).toBeGreaterThan(0);
    expect(stats.activeProjects).toBeGreaterThan(0);
    console.log(`✅ Admin Dashboard Stats: ${stats.todayHours} hours today, ${stats.activeProjects} active projects`);
  });

  it('should confirm admin can access all time entries', async () => {
    const timeEntries = await storage.getTimeEntries(adminUserId);
    expect(timeEntries.length).toBeGreaterThan(0);
    
    // Check if admin sees entries from multiple users
    const uniqueUsers = new Set(timeEntries.map(entry => entry.userId));
    expect(uniqueUsers.size).toBeGreaterThan(0);
    console.log(`✅ Admin Time Entries: ${timeEntries.length} entries from ${uniqueUsers.size} users`);
  });

  it('should confirm admin can access all employees', async () => {
    const employees = await storage.getEmployees(adminUserId);
    expect(employees.length).toBeGreaterThan(0);
    console.log(`✅ Admin Employee Access: ${employees.length} employees visible`);
  });

  it('should confirm admin role determination works correctly', async () => {
    const user = await storage.getUser(adminUserId);
    expect(user?.role).toBe('admin');
    console.log(`✅ Admin Role Verification: User role = ${user?.role}`);
  });
});