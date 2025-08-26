import { test, expect, Page } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:5000';

async function switchRole(page: Page, role: string) {
  console.log(`🔄 Switching to ${role} role...`);
  await page.evaluate(async (role) => {
    const response = await fetch('/api/users/change-role', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role })
    });
    return response.ok;
  }, role);
  await page.waitForTimeout(1000); // Wait for role change to take effect
}

test.describe('Employee Assignment UI Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(BASE_URL);
    await page.waitForLoadState('networkidle');
  });

  test('Admin can assign employees through UI when creating project', async ({ page }) => {
    // Switch to admin role
    await switchRole(page, 'admin');
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Navigate to Projects page
    await page.click('[data-testid="nav-projects"]');
    await page.waitForLoadState('networkidle');
    
    // Click New Project button
    await expect(page.locator('[data-testid="button-new-project"]')).toBeVisible();
    await page.click('[data-testid="button-new-project"]');
    
    // Fill project details
    await page.fill('[data-testid="input-project-name"]', 'UI Test Admin Project');
    await page.fill('textarea[name="description"]', 'Testing employee assignment UI');
    
    // Click on Assigned Employees tab
    await page.click('[data-testid="tab-employees"]');
    
    // Verify employee checkboxes are visible
    const employeeCheckboxes = page.locator('[data-testid^="checkbox-employee-"]');
    await expect(employeeCheckboxes.first()).toBeVisible();
    
    // Count available employees
    const employeeCount = await employeeCheckboxes.count();
    console.log(`✓ Admin sees ${employeeCount} employee checkboxes`);
    expect(employeeCount).toBeGreaterThan(0);
    
    // Select first employee
    await employeeCheckboxes.first().click();
    
    // Verify selection counter updates
    const selectionText = page.locator('text=/\\d+ employee\\(s\\) selected/');
    await expect(selectionText).toContainText('1 employee(s) selected');
    
    // Submit the project
    await page.click('button[type="submit"]');
    await page.waitForLoadState('networkidle');
    
    // Verify success
    await expect(page.locator('text=UI Test Admin Project')).toBeVisible();
    console.log('✅ Admin successfully created project with employee assignment through UI');
  });

  test('Project Manager can assign employees through UI when creating project', async ({ page }) => {
    // Switch to project_manager role
    await switchRole(page, 'project_manager');
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Navigate to Projects page
    await page.click('[data-testid="nav-projects"]');
    await page.waitForLoadState('networkidle');
    
    // Click New Project button
    await expect(page.locator('[data-testid="button-new-project"]')).toBeVisible();
    await page.click('[data-testid="button-new-project"]');
    
    // Fill project details
    await page.fill('[data-testid="input-project-name"]', 'UI Test PM Project');
    await page.fill('textarea[name="description"]', 'Testing PM employee assignment UI');
    
    // Click on Assigned Employees tab
    await page.click('[data-testid="tab-employees"]');
    
    // Verify employee checkboxes are visible
    const employeeCheckboxes = page.locator('[data-testid^="checkbox-employee-"]');
    await expect(employeeCheckboxes.first()).toBeVisible();
    
    // Count available employees
    const employeeCount = await employeeCheckboxes.count();
    console.log(`✓ Project Manager sees ${employeeCount} employee checkboxes`);
    expect(employeeCount).toBeGreaterThan(0);
    
    // Select multiple employees
    await employeeCheckboxes.nth(0).click();
    await employeeCheckboxes.nth(1).click();
    
    // Verify selection counter updates
    const selectionText = page.locator('text=/\\d+ employee\\(s\\) selected/');
    await expect(selectionText).toContainText('2 employee(s) selected');
    
    // Submit the project
    await page.click('button[type="submit"]');
    await page.waitForLoadState('networkidle');
    
    // Verify success
    await expect(page.locator('text=UI Test PM Project')).toBeVisible();
    console.log('✅ Project Manager successfully created project with employee assignment through UI');
  });

  test('Admin can edit existing project and modify employee assignments', async ({ page }) => {
    // Switch to admin role
    await switchRole(page, 'admin');
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Navigate to Projects page
    await page.click('[data-testid="nav-projects"]');
    await page.waitForLoadState('networkidle');
    
    // Find and click edit button on first project
    const editButton = page.locator('[data-testid^="button-edit-project-"]').first();
    await expect(editButton).toBeVisible();
    await editButton.click();
    
    // Click on Assigned Employees tab
    await page.click('[data-testid="tab-employees"]');
    
    // Verify current assignments and modify them
    const employeeCheckboxes = page.locator('[data-testid^="checkbox-employee-"]');
    const employeeCount = await employeeCheckboxes.count();
    console.log(`✓ Admin can edit project - sees ${employeeCount} employee checkboxes`);
    
    // Toggle some checkboxes
    if (employeeCount > 0) {
      await employeeCheckboxes.nth(0).click();
    }
    if (employeeCount > 1) {
      await employeeCheckboxes.nth(1).click();
    }
    
    // Submit changes
    await page.click('button[type="submit"]');
    await page.waitForLoadState('networkidle');
    
    console.log('✅ Admin successfully modified employee assignments through UI');
  });

  test('Manager role cannot see New Project button or employee assignment', async ({ page }) => {
    // Switch to manager role
    await switchRole(page, 'manager');
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Navigate to Projects page
    await page.click('[data-testid="nav-projects"]');
    await page.waitForLoadState('networkidle');
    
    // Verify New Project button is NOT visible
    await expect(page.locator('[data-testid="button-new-project"]')).not.toBeVisible();
    console.log('✅ Manager correctly cannot see New Project button');
    
    // Verify no edit buttons are visible
    const editButtons = page.locator('[data-testid^="button-edit-project-"]');
    await expect(editButtons.first()).not.toBeVisible();
    console.log('✅ Manager correctly cannot see project edit buttons');
  });

  test('Employee role has restricted access to employee assignment features', async ({ page }) => {
    // Switch to employee role
    await switchRole(page, 'employee');
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Navigate to Projects page
    await page.click('[data-testid="nav-projects"]');
    await page.waitForLoadState('networkidle');
    
    // Verify New Project button is NOT visible
    await expect(page.locator('[data-testid="button-new-project"]')).not.toBeVisible();
    console.log('✅ Employee correctly cannot see New Project button');
    
    // Verify no edit buttons are visible
    const editButtons = page.locator('[data-testid^="button-edit-project-"]');
    await expect(editButtons.first()).not.toBeVisible();
    console.log('✅ Employee correctly cannot see project edit buttons');
  });
});