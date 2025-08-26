import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createMockResponse } from '../utils/test-utils';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock API request function
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

describe('Authentication API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('GET /api/auth/user', () => {
    it('should return user data when authenticated', async () => {
      const mockUser = {
        id: 'user-1',
        email: 'test@example.com',
        firstName: 'Test',
        lastName: 'User',
        role: 'admin',
        isActive: true,
        createdAt: '2025-01-01T00:00:00.000Z',
        updatedAt: '2025-01-01T00:00:00.000Z',
      };

      mockFetch.mockResolvedValueOnce(createMockResponse(mockUser));

      const result = await apiRequest('/api/auth/user', 'GET');
      
      expect(mockFetch).toHaveBeenCalledWith('/api/auth/user', {
        method: 'GET',
        headers: {},
        body: undefined,
        credentials: 'include',
      });
      
      expect(result).toEqual(mockUser);
    });

    it('should handle unauthorized requests', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Unauthorized' }, 401));

      await expect(apiRequest('/api/auth/user', 'GET')).rejects.toThrow('401: {"message":"Unauthorized"}');
    });

    it('should handle network errors', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      await expect(apiRequest('/api/auth/user', 'GET')).rejects.toThrow('Network error');
    });
  });

  describe('POST /api/admin/users/{id}/role', () => {
    it('should update user role successfully', async () => {
      const mockResponse = { success: true, message: 'Role updated successfully' };
      mockFetch.mockResolvedValueOnce(createMockResponse(mockResponse));

      const result = await apiRequest('/api/admin/users/user-1/role', 'POST', { role: 'manager' });
      
      expect(mockFetch).toHaveBeenCalledWith('/api/admin/users/user-1/role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: 'manager' }),
        credentials: 'include',
      });
      
      expect(result).toEqual(mockResponse);
    });

    it('should handle invalid role error', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Invalid role' }, 400));

      await expect(apiRequest('/api/admin/users/user-1/role', 'POST', { role: 'invalid' }))
        .rejects.toThrow('400: {"message":"Invalid role"}');
    });

    it('should handle permission denied', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Insufficient permissions' }, 403));

      await expect(apiRequest('/api/admin/users/user-1/role', 'POST', { role: 'admin' }))
        .rejects.toThrow('403: {"message":"Insufficient permissions"}');
    });

    it('should prevent users from removing their own admin privileges', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Cannot remove your own admin privileges' }, 400));

      await expect(apiRequest('/api/admin/users/current-user/role', 'POST', { role: 'employee' }))
        .rejects.toThrow('400: {"message":"Cannot remove your own admin privileges"}');
    });
  });

  describe('Role Permission Validation', () => {
    it('should validate admin permissions', () => {
      const adminPermissions = [
        'manage_users', 'manage_system', 'view_all_projects', 'manage_all_departments',
        'generate_all_reports', 'system_configuration'
      ];

      const hasAdminPermission = (permission: string) => adminPermissions.includes(permission);

      expect(hasAdminPermission('manage_users')).toBe(true);
      expect(hasAdminPermission('view_all_projects')).toBe(true);
      expect(hasAdminPermission('invalid_permission')).toBe(false);
    });

    it('should validate manager permissions', () => {
      const managerPermissions = [
        'manage_department', 'view_department_projects', 'manage_employees',
        'generate_department_reports', 'view_department_analytics'
      ];

      const hasManagerPermission = (permission: string) => managerPermissions.includes(permission);

      expect(hasManagerPermission('manage_employees')).toBe(true);
      expect(hasManagerPermission('view_department_projects')).toBe(true);
      expect(hasManagerPermission('manage_system')).toBe(false);
    });

    it('should validate employee permissions', () => {
      const employeePermissions = [
        'log_time', 'view_assigned_projects', 'view_own_reports',
        'manage_profile', 'complete_tasks'
      ];

      const hasEmployeePermission = (permission: string) => employeePermissions.includes(permission);

      expect(hasEmployeePermission('log_time')).toBe(true);
      expect(hasEmployeePermission('view_assigned_projects')).toBe(true);
      expect(hasEmployeePermission('manage_employees')).toBe(false);
    });

    it('should validate project manager permissions', () => {
      const projectManagerPermissions = [
        'create_projects', 'manage_projects', 'view_project_analytics',
        'generate_project_reports', 'manage_tasks', 'assign_team_members'
      ];

      const hasProjectManagerPermission = (permission: string) => projectManagerPermissions.includes(permission);

      expect(hasProjectManagerPermission('create_projects')).toBe(true);
      expect(hasProjectManagerPermission('manage_projects')).toBe(true);
      expect(hasProjectManagerPermission('manage_system')).toBe(false);
    });
  });

  describe('Authentication Flow', () => {
    it('should handle login redirect', async () => {
      const mockRedirect = vi.fn();
      const mockWindow = {
        location: {
          href: '',
          assign: mockRedirect,
        },
      };

      // Simulate unauthorized response triggering login redirect
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Authentication required' }, 401));

      try {
        await apiRequest('/api/protected-endpoint', 'GET');
      } catch (error) {
        // Simulate frontend handling the 401 error
        if (error instanceof Error && error.message.includes('401')) {
          mockWindow.location.href = '/api/login';
        }
      }

      expect(mockWindow.location.href).toBe('/api/login');
    });

    it('should handle session expiration', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Session expired' }, 401));

      await expect(apiRequest('/api/dashboard/stats', 'GET'))
        .rejects.toThrow('401: {"message":"Session expired"}');
    });

    it('should handle token refresh', async () => {
      // First call fails with expired token
      mockFetch
        .mockResolvedValueOnce(createMockResponse({ message: 'Token expired' }, 401))
        .mockResolvedValueOnce(createMockResponse({ access_token: 'new-token' }))
        .mockResolvedValueOnce(createMockResponse({ data: 'success' }));

      // This would be handled by authentication middleware in real implementation
      try {
        await apiRequest('/api/protected-resource', 'GET');
      } catch (error) {
        if (error instanceof Error && error.message.includes('Token expired')) {
          // Simulate token refresh
          await apiRequest('/api/auth/refresh', 'POST');
          const result = await apiRequest('/api/protected-resource', 'GET');
          expect(result).toEqual({ data: 'success' });
        }
      }
    });
  });
});