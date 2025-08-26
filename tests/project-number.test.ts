import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { db } from '../server/db';
import { projects, users } from '../shared/schema';
import { eq } from 'drizzle-orm';

describe('Project Number Field Tests', () => {
  let testUserId: string;
  let testProjectId: string;

  beforeEach(async () => {
    // Create a test user
    const [user] = await db.insert(users).values({
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User',
      role: 'admin'
    }).returning();
    testUserId = user.id;
  });

  afterEach(async () => {
    // Clean up test data
    if (testProjectId) {
      await db.delete(projects).where(eq(projects.id, testProjectId));
    }
    await db.delete(users).where(eq(users.id, testUserId));
  });

  describe('Database Schema', () => {
    it('should create project without project number', async () => {
      const [project] = await db.insert(projects).values({
        name: 'Test Project',
        description: 'Test Description',
        userId: testUserId,
        color: '#1976D2',
        isEnterpriseWide: true
      }).returning();

      testProjectId = project.id;
      expect(project.projectNumber).toBeNull();
      expect(project.name).toBe('Test Project');
    });

    it('should create project with project number', async () => {
      const [project] = await db.insert(projects).values({
        name: 'Test Project with Number',
        projectNumber: 'PRJ-001',
        description: 'Test Description',
        userId: testUserId,
        color: '#1976D2',
        isEnterpriseWide: true
      }).returning();

      testProjectId = project.id;
      expect(project.projectNumber).toBe('PRJ-001');
      expect(project.name).toBe('Test Project with Number');
    });

    it('should handle alphanumeric project numbers', async () => {
      const testCases = [
        'PRJ-001',
        '2024-001',
        'ABC123',
        'PROJECT_001',
        'P1',
        'WEB-DEV-2024'
      ];

      for (const projectNumber of testCases) {
        const [project] = await db.insert(projects).values({
          name: `Test Project ${projectNumber}`,
          projectNumber,
          userId: testUserId,
          color: '#1976D2',
          isEnterpriseWide: true
        }).returning();

        expect(project.projectNumber).toBe(projectNumber);
        
        // Clean up for next iteration
        await db.delete(projects).where(eq(projects.id, project.id));
      }
    });

    it('should update project number', async () => {
      const [project] = await db.insert(projects).values({
        name: 'Test Project Update',
        projectNumber: 'PRJ-001',
        userId: testUserId,
        color: '#1976D2',
        isEnterpriseWide: true
      }).returning();

      testProjectId = project.id;

      // Update project number
      const [updatedProject] = await db.update(projects)
        .set({ projectNumber: 'PRJ-002' })
        .where(eq(projects.id, project.id))
        .returning();

      expect(updatedProject.projectNumber).toBe('PRJ-002');
    });

    it('should clear project number by setting to null', async () => {
      const [project] = await db.insert(projects).values({
        name: 'Test Project Clear',
        projectNumber: 'PRJ-001',
        userId: testUserId,
        color: '#1976D2',
        isEnterpriseWide: true
      }).returning();

      testProjectId = project.id;

      // Clear project number
      const [updatedProject] = await db.update(projects)
        .set({ projectNumber: null })
        .where(eq(projects.id, project.id))
        .returning();

      expect(updatedProject.projectNumber).toBeNull();
    });
  });

  describe('Schema Validation', () => {
    it('should validate project number length constraints', async () => {
      // Test maximum length (50 characters)
      const longProjectNumber = 'A'.repeat(50);
      
      const [project] = await db.insert(projects).values({
        name: 'Test Long Project Number',
        projectNumber: longProjectNumber,
        userId: testUserId,
        color: '#1976D2',
        isEnterpriseWide: true
      }).returning();

      testProjectId = project.id;
      expect(project.projectNumber).toBe(longProjectNumber);
    });

    it('should handle empty string as project number', async () => {
      const [project] = await db.insert(projects).values({
        name: 'Test Empty Project Number',
        projectNumber: '',
        userId: testUserId,
        color: '#1976D2',
        isEnterpriseWide: true
      }).returning();

      testProjectId = project.id;
      expect(project.projectNumber).toBe('');
    });
  });

  describe('Query Operations', () => {
    it('should filter projects by project number', async () => {
      // Create multiple projects with different project numbers
      const projects1 = await db.insert(projects).values([
        {
          name: 'Project A',
          projectNumber: 'PRJ-001',
          userId: testUserId,
          color: '#1976D2',
          isEnterpriseWide: true
        },
        {
          name: 'Project B',
          projectNumber: 'PRJ-002',
          userId: testUserId,
          color: '#1976D2',
          isEnterpriseWide: true
        },
        {
          name: 'Project C',
          projectNumber: null,
          userId: testUserId,
          color: '#1976D2',
          isEnterpriseWide: true
        }
      ]).returning();

      // Find project by project number
      const foundProjects = await db.select()
        .from(projects)
        .where(eq(projects.projectNumber, 'PRJ-001'));

      expect(foundProjects).toHaveLength(1);
      expect(foundProjects[0].name).toBe('Project A');
      expect(foundProjects[0].projectNumber).toBe('PRJ-001');

      // Clean up
      for (const project of projects1) {
        await db.delete(projects).where(eq(projects.id, project.id));
      }
    });

    it('should handle projects with null project numbers', async () => {
      const [project] = await db.insert(projects).values({
        name: 'Project No Number',
        projectNumber: null,
        userId: testUserId,
        color: '#1976D2',
        isEnterpriseWide: true
      }).returning();

      testProjectId = project.id;

      const foundProjects = await db.select()
        .from(projects)
        .where(eq(projects.id, project.id));

      expect(foundProjects[0].projectNumber).toBeNull();
    });
  });
});