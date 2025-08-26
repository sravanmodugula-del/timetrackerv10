import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import { db } from '../server/db';
import { projects, users, sessions } from '../shared/schema';
import { eq } from 'drizzle-orm';

// Mock the express app
const mockApp = {
  post: vi.fn(),
  put: vi.fn(),
  get: vi.fn(),
  delete: vi.fn(),
  listen: vi.fn(),
};

describe('Project API with Project Number', () => {
  let testUserId: string;
  let sessionId: string;
  let agent: any;

  beforeEach(async () => {
    // Create test user
    const [user] = await db.insert(users).values({
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User',
      role: 'admin'
    }).returning();
    testUserId = user.id;

    // Create test session
    const [session] = await db.insert(sessions).values({
      sid: 'test-session-id',
      sess: {
        userId: testUserId,
        user: user,
        isAuthenticated: true
      },
      expire: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
    }).returning();
    sessionId = session.sid;

    // Create agent with session (mocked)
    agent = request.agent(mockApp as any);
  });

  afterEach(async () => {
    // Clean up test data
    await db.delete(projects).where(eq(projects.userId, testUserId));
    await db.delete(sessions).where(eq(sessions.sid, sessionId));
    await db.delete(users).where(eq(users.id, testUserId));
  });

  describe('POST /api/projects', () => {
    it('should create project without project number', async () => {
      const projectData = {
        name: 'Test Project',
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true
      };

      const response = await agent
        .post('/api/projects')
        .set('Cookie', `connect.sid=${sessionId}`)
        .send(projectData)
        .expect(200);

      expect(response.body.name).toBe('Test Project');
      expect(response.body.projectNumber).toBeNull();
    });

    it('should create project with project number', async () => {
      const projectData = {
        name: 'Test Project with Number',
        projectNumber: 'PRJ-001',
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true
      };

      const response = await agent
        .post('/api/projects')
        .set('Cookie', `connect.sid=${sessionId}`)
        .send(projectData)
        .expect(200);

      expect(response.body.name).toBe('Test Project with Number');
      expect(response.body.projectNumber).toBe('PRJ-001');
    });

    it('should handle empty project number', async () => {
      const projectData = {
        name: 'Test Project Empty Number',
        projectNumber: '',
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true
      };

      const response = await agent
        .post('/api/projects')
        .set('Cookie', `connect.sid=${sessionId}`)
        .send(projectData)
        .expect(200);

      expect(response.body.name).toBe('Test Project Empty Number');
      expect(response.body.projectNumber).toBe('');
    });

    it('should validate project number format', async () => {
      const testCases = [
        'PRJ-001',
        '2024-WEB-001',
        'ABC123',
        'PROJECT_001',
        'P1',
        'WEB-DEV-2024-ALPHA'
      ];

      for (const projectNumber of testCases) {
        const projectData = {
          name: `Test Project ${projectNumber}`,
          projectNumber,
          description: 'Test Description',
          color: '#1976D2',
          isEnterpriseWide: true
        };

        const response = await agent
          .post('/api/projects')
          .set('Cookie', `connect.sid=${sessionId}`)
          .send(projectData)
          .expect(200);

        expect(response.body.projectNumber).toBe(projectNumber);
      }
    });
  });

  describe('PUT /api/projects/:id', () => {
    let projectId: string;

    beforeEach(async () => {
      const [project] = await db.insert(projects).values({
        name: 'Test Project for Update',
        projectNumber: 'PRJ-001',
        userId: testUserId,
        color: '#1976D2',
        isEnterpriseWide: true
      }).returning();
      projectId = project.id;
    });

    it('should update project number', async () => {
      const updateData = {
        name: 'Updated Project',
        projectNumber: 'PRJ-002',
        description: 'Updated Description',
        color: '#388E3C',
        isEnterpriseWide: false
      };

      const response = await agent
        .put(`/api/projects/${projectId}`)
        .set('Cookie', `connect.sid=${sessionId}`)
        .send(updateData)
        .expect(200);

      expect(response.body.projectNumber).toBe('PRJ-002');
      expect(response.body.name).toBe('Updated Project');
    });

    it('should clear project number', async () => {
      const updateData = {
        name: 'Project No Number',
        projectNumber: null,
        description: 'No project number',
        color: '#1976D2',
        isEnterpriseWide: true
      };

      const response = await agent
        .put(`/api/projects/${projectId}`)
        .set('Cookie', `connect.sid=${sessionId}`)
        .send(updateData)
        .expect(200);

      expect(response.body.projectNumber).toBeNull();
    });

    it('should update project keeping existing project number', async () => {
      const updateData = {
        name: 'Updated Name Only',
        description: 'Updated description only',
        color: '#F57C00',
        isEnterpriseWide: true
        // projectNumber not included - should keep existing
      };

      const response = await agent
        .put(`/api/projects/${projectId}`)
        .set('Cookie', `connect.sid=${sessionId}`)
        .send(updateData)
        .expect(200);

      expect(response.body.projectNumber).toBe('PRJ-001');
      expect(response.body.name).toBe('Updated Name Only');
    });
  });

  describe('GET /api/projects', () => {
    beforeEach(async () => {
      // Create test projects with various project numbers
      await db.insert(projects).values([
        {
          name: 'Project Alpha',
          projectNumber: 'PRJ-001',
          userId: testUserId,
          color: '#1976D2',
          isEnterpriseWide: true
        },
        {
          name: 'Project Beta',
          projectNumber: '2024-002',
          userId: testUserId,
          color: '#388E3C',
          isEnterpriseWide: true
        },
        {
          name: 'Project Gamma',
          projectNumber: null,
          userId: testUserId,
          color: '#F57C00',
          isEnterpriseWide: true
        }
      ]);
    });

    it('should return projects with project numbers', async () => {
      const response = await agent
        .get('/api/projects')
        .set('Cookie', `connect.sid=${sessionId}`)
        .expect(200);

      expect(response.body).toHaveLength(3);
      
      const projectAlpha = response.body.find((p: any) => p.name === 'Project Alpha');
      const projectBeta = response.body.find((p: any) => p.name === 'Project Beta');
      const projectGamma = response.body.find((p: any) => p.name === 'Project Gamma');

      expect(projectAlpha.projectNumber).toBe('PRJ-001');
      expect(projectBeta.projectNumber).toBe('2024-002');
      expect(projectGamma.projectNumber).toBeNull();
    });
  });

  describe('Validation Edge Cases', () => {
    it('should handle very long project number', async () => {
      const longProjectNumber = 'A'.repeat(50); // Max length
      
      const projectData = {
        name: 'Long Project Number Test',
        projectNumber: longProjectNumber,
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true
      };

      const response = await agent
        .post('/api/projects')
        .set('Cookie', `connect.sid=${sessionId}`)
        .send(projectData)
        .expect(200);

      expect(response.body.projectNumber).toBe(longProjectNumber);
    });

    it('should reject project number that exceeds length limit', async () => {
      const tooLongProjectNumber = 'A'.repeat(51); // Over limit
      
      const projectData = {
        name: 'Too Long Project Number Test',
        projectNumber: tooLongProjectNumber,
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true
      };

      // This should fail validation
      await agent
        .post('/api/projects')
        .set('Cookie', `connect.sid=${sessionId}`)
        .send(projectData)
        .expect(400);
    });
  });
});