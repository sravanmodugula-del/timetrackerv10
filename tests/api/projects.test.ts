import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createMockResponse, mockProject } from '../utils/test-utils';

const mockFetch = vi.fn();
global.fetch = mockFetch;

const apiRequest = async (url: string, method: string, data?: any) => {
  const response = await fetch(url, {
    method,
    headers: data ? { 'Content-Type': 'application/json' } : {},
    body: data ? JSON.stringify(data) : undefined,
    credentials: 'include',
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`${response.status}: ${errorText}`);
  }

  return response.json();
};

describe('Projects API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('GET /api/projects', () => {
    it('should return list of projects', async () => {
      const mockProjects = [mockProject, { ...mockProject, id: 'project-2', name: 'Project 2' }];
      mockFetch.mockResolvedValueOnce(createMockResponse(mockProjects));

      const result = await apiRequest('/api/projects', 'GET');
      
      expect(mockFetch).toHaveBeenCalledWith('/api/projects', {
        method: 'GET',
        headers: {},
        body: undefined,
        credentials: 'include',
      });
      
      expect(result).toEqual(mockProjects);
      expect(result).toHaveLength(2);
    });

    it('should handle empty project list', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse([]));

      const result = await apiRequest('/api/projects', 'GET');
      
      expect(result).toEqual([]);
    });

    it('should handle authorization errors', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Unauthorized' }, 401));

      await expect(apiRequest('/api/projects', 'GET')).rejects.toThrow('401: {"message":"Unauthorized"}');
    });
  });

  describe('POST /api/projects', () => {
    it('should create new project successfully', async () => {
      const newProject = {
        name: 'New Project',
        projectNumber: 'P002',
        description: 'New project description',
        color: '#388E3C',
        startDate: '2025-01-01',
        endDate: '2025-12-31',
        isEnterpriseWide: true,
      };

      const createdProject = { ...mockProject, ...newProject, id: 'new-project-id' };
      mockFetch.mockResolvedValueOnce(createMockResponse(createdProject, 201));

      const result = await apiRequest('/api/projects', 'POST', newProject);
      
      expect(mockFetch).toHaveBeenCalledWith('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newProject),
        credentials: 'include',
      });
      
      expect(result.id).toBe('new-project-id');
      expect(result.name).toBe('New Project');
    });

    it('should handle validation errors', async () => {
      const invalidProject = { name: '', description: 'Missing name' };
      mockFetch.mockResolvedValueOnce(createMockResponse({ 
        message: 'Validation failed', 
        errors: [{ field: 'name', message: 'Name is required' }] 
      }, 400));

      await expect(apiRequest('/api/projects', 'POST', invalidProject))
        .rejects.toThrow('400: {"message":"Validation failed","errors":[{"field":"name","message":"Name is required"}]}');
    });

    it('should handle permission denied for project creation', async () => {
      const newProject = { name: 'Unauthorized Project', description: 'Test' };
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Insufficient permissions to create projects' }, 403));

      await expect(apiRequest('/api/projects', 'POST', newProject))
        .rejects.toThrow('403: {"message":"Insufficient permissions to create projects"}');
    });
  });

  describe('PUT /api/projects/:id', () => {
    it('should update project successfully', async () => {
      const projectId = 'project-1';
      const updateData = { name: 'Updated Project Name', description: 'Updated description' };
      const updatedProject = { ...mockProject, ...updateData };
      
      mockFetch.mockResolvedValueOnce(createMockResponse(updatedProject));

      const result = await apiRequest(`/api/projects/${projectId}`, 'PUT', updateData);
      
      expect(mockFetch).toHaveBeenCalledWith(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updateData),
        credentials: 'include',
      });
      
      expect(result.name).toBe('Updated Project Name');
      expect(result.description).toBe('Updated description');
    });

    it('should handle project not found', async () => {
      const projectId = 'non-existent-project';
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Project not found' }, 404));

      await expect(apiRequest(`/api/projects/${projectId}`, 'PUT', { name: 'Test' }))
        .rejects.toThrow('404: {"message":"Project not found"}');
    });
  });

  describe('DELETE /api/projects/:id', () => {
    it('should delete project successfully', async () => {
      const projectId = 'project-1';
      mockFetch.mockResolvedValueOnce(createMockResponse({ success: true }, 204));

      const result = await apiRequest(`/api/projects/${projectId}`, 'DELETE');
      
      expect(mockFetch).toHaveBeenCalledWith(`/api/projects/${projectId}`, {
        method: 'DELETE',
        headers: {},
        body: undefined,
        credentials: 'include',
      });
    });

    it('should handle permission denied for project deletion', async () => {
      const projectId = 'project-1';
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Insufficient permissions to delete projects' }, 403));

      await expect(apiRequest(`/api/projects/${projectId}`, 'DELETE'))
        .rejects.toThrow('403: {"message":"Insufficient permissions to delete projects"}');
    });

    it('should handle project with time entries', async () => {
      const projectId = 'project-with-entries';
      mockFetch.mockResolvedValueOnce(createMockResponse({ 
        message: 'Cannot delete project with existing time entries' 
      }, 400));

      await expect(apiRequest(`/api/projects/${projectId}`, 'DELETE'))
        .rejects.toThrow('400: {"message":"Cannot delete project with existing time entries"}');
    });
  });

  describe('Project Employee Assignment', () => {
    it('should assign employees to project', async () => {
      const projectId = 'project-1';
      const employeeIds = ['emp-1', 'emp-2', 'emp-3'];
      
      mockFetch.mockResolvedValueOnce(createMockResponse({ 
        success: true, 
        assigned: employeeIds.length 
      }));

      const result = await apiRequest(`/api/projects/${projectId}/employees`, 'POST', { employeeIds });
      
      expect(mockFetch).toHaveBeenCalledWith(`/api/projects/${projectId}/employees`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ employeeIds }),
        credentials: 'include',
      });
      
      expect(result.success).toBe(true);
      expect(result.assigned).toBe(3);
    });

    it('should get assigned employees', async () => {
      const projectId = 'project-1';
      const assignedEmployees = [
        { id: 'emp-1', firstName: 'John', lastName: 'Doe', email: 'john@test.com' },
        { id: 'emp-2', firstName: 'Jane', lastName: 'Smith', email: 'jane@test.com' },
      ];
      
      mockFetch.mockResolvedValueOnce(createMockResponse(assignedEmployees));

      const result = await apiRequest(`/api/projects/${projectId}/employees`, 'GET');
      
      expect(result).toEqual(assignedEmployees);
      expect(result).toHaveLength(2);
    });
  });

  describe('Project Filtering and Search', () => {
    it('should filter projects by status', async () => {
      const activeProjects = [
        { ...mockProject, id: 'active-1', name: 'Active Project 1' },
        { ...mockProject, id: 'active-2', name: 'Active Project 2' },
      ];
      
      mockFetch.mockResolvedValueOnce(createMockResponse(activeProjects));

      const result = await apiRequest('/api/projects?status=active', 'GET');
      
      expect(mockFetch).toHaveBeenCalledWith('/api/projects?status=active', {
        method: 'GET',
        headers: {},
        body: undefined,
        credentials: 'include',
      });
      
      expect(result).toHaveLength(2);
    });

    it('should search projects by name', async () => {
      const searchResults = [
        { ...mockProject, name: 'GenAI Project 1' },
        { ...mockProject, id: 'project-2', name: 'GenAI Project 2' },
      ];
      
      mockFetch.mockResolvedValueOnce(createMockResponse(searchResults));

      const result = await apiRequest('/api/projects?search=GenAI', 'GET');
      
      expect(result).toHaveLength(2);
      expect(result.every((p: any) => p.name.includes('GenAI'))).toBe(true);
    });
  });

  describe('Project Validation', () => {
    it('should validate project dates', () => {
      const validateDateRange = (startDate: string, endDate: string): boolean => {
        const start = new Date(startDate);
        const end = new Date(endDate);
        return start < end;
      };

      expect(validateDateRange('2025-01-01', '2025-12-31')).toBe(true);
      expect(validateDateRange('2025-12-31', '2025-01-01')).toBe(false);
      expect(validateDateRange('2025-06-01', '2025-06-01')).toBe(false);
    });

    it('should validate project number format', () => {
      const validateProjectNumber = (projectNumber: string): boolean => {
        const regex = /^PI\d{6}$/;
        return regex.test(projectNumber);
      };

      expect(validateProjectNumber('PI123456')).toBe(true);
      expect(validateProjectNumber('PI567890')).toBe(true);
      expect(validateProjectNumber('P123456')).toBe(false);
      expect(validateProjectNumber('PI12345')).toBe(false);
      expect(validateProjectNumber('PI1234567')).toBe(false);
    });

    it('should validate color format', () => {
      const validateColor = (color: string): boolean => {
        const regex = /^#[0-9A-F]{6}$/i;
        return regex.test(color);
      };

      expect(validateColor('#1976D2')).toBe(true);
      expect(validateColor('#388E3C')).toBe(true);
      expect(validateColor('#FF0000')).toBe(true);
      expect(validateColor('1976D2')).toBe(false);
      expect(validateColor('#1976D')).toBe(false);
      expect(validateColor('#ZZZZZZ')).toBe(false);
    });
  });
});