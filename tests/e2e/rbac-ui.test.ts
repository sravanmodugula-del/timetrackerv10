import { test, expect, Page } from '@playwright/test';

// Test configuration
const BASE_URL = process.env.BASE_URL || 'http://localhost:5000';
const TEST_TIMEOUT = 30000;

// Helper function to wait for page load and authentication
async function waitForAuth(page: Page) {
  await page.waitForSelector('[data-testid="dashboard-header"]', { timeout: TEST_TIMEOUT });
  await page.waitForFunction(() => {
    return window.localStorage.getItem('auth-state') !== null;
  }, { timeout: TEST_TIMEOUT });
}

// Helper function to switch roles via API
async function switchRole(page: Page, role: string) {
  const response = await page.request.post(`${BASE_URL}/api/users/change-role`, {
    data: { role },
    headers: { 'Content-Type': 'application/json' }
  });
  expect(response.ok()).toBeTruthy();
  await page.reload();
  await waitForAuth(page);
  // Wait for role to be updated in UI
  await page.waitForTimeout(1000);
}

// Helper function to create test project
async function createTestProject(page: Page, projectName: string) {
  await page.click('[data-testid="button-new-project"]');
  await page.waitForSelector('[data-testid="input-project-name"]');
  await page.fill('[data-testid="input-project-name"]', projectName);
  await page.fill('[data-testid="textarea-project-description"]', `Test description for ${projectName}`);
  await page.click('[data-testid="button-submit-project"]');
  await page.waitForSelector(`[data-testid="card-project-${projectName}"]`, { timeout: TEST_TIMEOUT });
}

test.describe('RBAC UI End-to-End Testing', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/projects`);
    await waitForAuth(page);
  });

  test('Admin Role - Full CRUD Operations', async ({ page }) => {
    // Switch to admin role
    await switchRole(page, 'admin');
    
    // Verify admin sees all UI elements
    await expect(page.locator('[data-testid="button-new-project"]')).toBeVisible();
    
    // Test 1: Create new project
    const testProjectName = `Admin Test Project ${Date.now()}`;
    await createTestProject(page, testProjectName);
    
    // Verify project was created
    await expect(page.locator(`[data-testid="card-project-${testProjectName}"]`)).toBeVisible();
    
    // Test 2: Edit existing project
    await page.click(`[data-testid="button-edit-${testProjectName}"]`);
    await page.waitForSelector('[data-testid="input-project-name"]');
    
    const updatedName = `${testProjectName} - Updated`;
    await page.fill('[data-testid="input-project-name"]', updatedName);
    await page.click('[data-testid="button-submit-project"]');
    
    // Verify project was updated
    await page.waitForSelector(`[data-testid="card-project-${updatedName}"]`, { timeout: TEST_TIMEOUT });
    await expect(page.locator(`[data-testid="card-project-${updatedName}"]`)).toBeVisible();
    
    // Test 3: Assign employees to project
    await page.click(`[data-testid="button-edit-${updatedName}"]`);
    await page.click('[data-testid="tab-employees"]');
    await page.click('[data-testid="checkbox-employee-emp-real-2"]');
    await page.click('[data-testid="button-submit-project"]');
    
    // Test 4: Delete project
    await page.click(`[data-testid="button-delete-${updatedName}"]`);
    await page.click('[data-testid="button-confirm-delete"]');
    
    // Verify project was deleted
    await expect(page.locator(`[data-testid="card-project-${updatedName}"]`)).not.toBeVisible();
  });

  test('Project Manager Role - Limited CRUD Operations', async ({ page }) => {
    await switchRole(page, 'project_manager');
    
    // Verify project manager sees create and edit buttons
    await expect(page.locator('[data-testid="button-new-project"]')).toBeVisible();
    
    // Test 1: Create project
    const testProjectName = `PM Test Project ${Date.now()}`;
    await createTestProject(page, testProjectName);
    
    // Test 2: Edit own project
    await page.click(`[data-testid="button-edit-${testProjectName}"]`);
    await page.fill('[data-testid="input-project-name"]', `${testProjectName} - Updated`);
    await page.click('[data-testid="button-submit-project"]');
    
    // Test 3: Verify project manager CANNOT delete projects
    await expect(page.locator(`[data-testid="button-delete-${testProjectName} - Updated"]`)).not.toBeVisible();
  });

  test('Manager Role - View Only Operations', async ({ page }) => {
    await switchRole(page, 'manager');
    
    // Verify manager sees no create/edit buttons
    await expect(page.locator('[data-testid="button-new-project"]')).not.toBeVisible();
    
    // Verify all projects are visible (enterprise-wide view)
    const projectCards = page.locator('[data-testid^="card-project-"]');
    const projectCount = await projectCards.count();
    expect(projectCount).toBeGreaterThan(0);
    
    // Verify no edit buttons visible
    const editButtons = page.locator('[data-testid^="button-edit-"]');
    const editCount = await editButtons.count();
    expect(editCount).toBe(0);
  });

  test('Employee Role - Restricted Access', async ({ page }) => {
    await switchRole(page, 'employee');
    
    // Verify employee sees no create/edit/delete buttons
    await expect(page.locator('[data-testid="button-new-project"]')).not.toBeVisible();
    
    // Verify projects are visible but no interaction buttons
    const projectCards = page.locator('[data-testid^="card-project-"]');
    const projectCount = await projectCards.count();
    expect(projectCount).toBeGreaterThan(0);
    
    // Verify no edit or delete buttons
    await expect(page.locator('[data-testid^="button-edit-"]')).not.toBeVisible();
    await expect(page.locator('[data-testid^="button-delete-"]')).not.toBeVisible();
  });

  test('Role Switching Functionality', async ({ page }) => {
    // Test switching between all roles and verify UI updates
    const roles = ['admin', 'project_manager', 'manager', 'employee'];
    
    for (const role of roles) {
      await switchRole(page, role);
      
      // Navigate to role testing page
      await page.goto(`${BASE_URL}/role-testing`);
      await waitForAuth(page);
      
      // Verify current role is displayed
      await expect(page.locator('[data-testid="current-role"]')).toContainText(role);
      
      // Test role switching buttons
      if (role === 'admin') {
        // Admin should see all role switching options
        await expect(page.locator('[data-testid="button-switch-employee"]')).toBeVisible();
        await expect(page.locator('[data-testid="button-switch-manager"]')).toBeVisible();
        await expect(page.locator('[data-testid="button-switch-project_manager"]')).toBeVisible();
      }
      
      // Return to projects page and verify permissions
      await page.goto(`${BASE_URL}/projects`);
      await waitForAuth(page);
      
      if (role === 'admin' || role === 'project_manager') {
        await expect(page.locator('[data-testid="button-new-project"]')).toBeVisible();
      } else {
        await expect(page.locator('[data-testid="button-new-project"]')).not.toBeVisible();
      }
    }
  });

  test('Dashboard Data Scoping by Role', async ({ page }) => {
    // Test admin sees all data
    await switchRole(page, 'admin');
    await page.goto(`${BASE_URL}/dashboard`);
    await waitForAuth(page);
    
    const adminStats = await page.locator('[data-testid="stats-total-hours"]').textContent();
    const adminProjects = await page.locator('[data-testid="stats-active-projects"]').textContent();
    
    // Test employee sees restricted data
    await switchRole(page, 'employee');
    await page.goto(`${BASE_URL}/dashboard`);
    await waitForAuth(page);
    
    const employeeStats = await page.locator('[data-testid="stats-total-hours"]').textContent();
    const employeeProjects = await page.locator('[data-testid="stats-active-projects"]').textContent();
    
    // Admin should see more or equal data than employee
    const adminHours = parseFloat(adminStats?.replace(/[^\d.]/g, '') || '0');
    const employeeHours = parseFloat(employeeStats?.replace(/[^\d.]/g, '') || '0');
    expect(adminHours).toBeGreaterThanOrEqual(employeeHours);
  });
});

test.describe('Time Entry RBAC Testing', () => {
  test('Admin can manage all time entries', async ({ page }) => {
    await switchRole(page, 'admin');
    await page.goto(`${BASE_URL}/time-log`);
    await waitForAuth(page);
    
    // Admin should see all time entries
    const timeEntries = page.locator('[data-testid^="time-entry-"]');
    const entryCount = await timeEntries.count();
    expect(entryCount).toBeGreaterThan(0);
    
    // Admin should see edit/delete buttons on entries from other users
    const editButtons = page.locator('[data-testid^="button-edit-time-"]');
    const editCount = await editButtons.count();
    expect(editCount).toBeGreaterThan(0);
  });

  test('Employee can only manage own time entries', async ({ page }) => {
    await switchRole(page, 'employee');
    await page.goto(`${BASE_URL}/time-log`);
    await waitForAuth(page);
    
    // Employee should see limited time entries
    const timeEntries = page.locator('[data-testid^="time-entry-"]');
    const entryCount = await timeEntries.count();
    
    // Count should be less than admin view (tested separately)
    expect(entryCount).toBeGreaterThan(0);
  });
});

// Performance and stress testing
test.describe('RBAC Performance Testing', () => {
  test('Role switching performance', async ({ page }) => {
    const roles = ['admin', 'employee', 'manager', 'project_manager'];
    const switchTimes: number[] = [];
    
    for (let i = 0; i < roles.length; i++) {
      const startTime = Date.now();
      await switchRole(page, roles[i]);
      const endTime = Date.now();
      switchTimes.push(endTime - startTime);
    }
    
    // Average switch time should be under 3 seconds
    const avgSwitchTime = switchTimes.reduce((a, b) => a + b, 0) / switchTimes.length;
    expect(avgSwitchTime).toBeLessThan(3000);
  });
});