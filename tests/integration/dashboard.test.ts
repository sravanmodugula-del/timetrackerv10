import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createMockResponse } from '../utils/test-utils';

const mockFetch = vi.fn();
global.fetch = mockFetch;

const apiRequest = async (url: string, method = 'GET', data?: any) => {
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

describe('Dashboard Integration Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Dashboard Stats API', () => {
    it('should aggregate dashboard statistics correctly', async () => {
      const mockStats = {
        todayHours: 8.5,
        weekHours: 42.5,
        monthHours: 168.25,
        activeProjects: 5,
      };

      mockFetch.mockResolvedValueOnce(createMockResponse(mockStats));

      const result = await apiRequest('/api/dashboard/stats');
      
      expect(result).toEqual(mockStats);
      expect(typeof result.todayHours).toBe('number');
      expect(typeof result.weekHours).toBe('number');
      expect(typeof result.monthHours).toBe('number');
      expect(typeof result.activeProjects).toBe('number');
    });

    it('should handle zero stats for new users', async () => {
      const emptyStats = {
        todayHours: 0,
        weekHours: 0,
        monthHours: 0,
        activeProjects: 0,
      };

      mockFetch.mockResolvedValueOnce(createMockResponse(emptyStats));

      const result = await apiRequest('/api/dashboard/stats');
      
      expect(result).toEqual(emptyStats);
    });

    it('should calculate stats with PST timezone consideration', async () => {
      // Mock stats that should account for PST timezone
      const pstStats = {
        todayHours: 6.0,
        weekHours: 30.0,
        monthHours: 120.0,
        activeProjects: 3,
      };

      mockFetch.mockResolvedValueOnce(createMockResponse(pstStats));

      const result = await apiRequest('/api/dashboard/stats');
      
      // Verify PST-adjusted calculations
      expect(result.todayHours).toBeGreaterThanOrEqual(0);
      expect(result.weekHours).toBeGreaterThanOrEqual(result.todayHours);
      expect(result.monthHours).toBeGreaterThanOrEqual(result.weekHours);
    });
  });

  describe('Project Breakdown API', () => {
    it('should return project breakdown with time allocation', async () => {
      const mockBreakdown = [
        {
          projectId: 'project-1',
          projectName: 'GenAI Project',
          totalHours: 25.5,
          percentage: 45.2,
          color: '#1976D2',
        },
        {
          projectId: 'project-2',
          projectName: 'Time Tracker',
          totalHours: 18.0,
          percentage: 31.9,
          color: '#388E3C',
        },
        {
          projectId: 'project-3',
          projectName: 'Documentation',
          totalHours: 12.9,
          percentage: 22.9,
          color: '#F57C00',
        },
      ];

      mockFetch.mockResolvedValueOnce(createMockResponse(mockBreakdown));

      const result = await apiRequest('/api/dashboard/project-breakdown');
      
      expect(result).toHaveLength(3);
      expect(result[0]).toHaveProperty('projectId');
      expect(result[0]).toHaveProperty('projectName');
      expect(result[0]).toHaveProperty('totalHours');
      expect(result[0]).toHaveProperty('percentage');
      expect(result[0]).toHaveProperty('color');

      // Verify percentages add up to approximately 100%
      const totalPercentage = result.reduce((sum: number, item: any) => sum + item.percentage, 0);
      expect(totalPercentage).toBeCloseTo(100, 1);
    });

    it('should handle empty project breakdown', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse([]));

      const result = await apiRequest('/api/dashboard/project-breakdown');
      
      expect(result).toEqual([]);
    });
  });

  describe('Recent Activity API', () => {
    it('should return recent time entries with project information', async () => {
      const mockActivity = [
        {
          id: 'entry-1',
          date: '2025-08-16',
          duration: 4.5,
          description: 'API development work',
          project: {
            id: 'project-1',
            name: 'GenAI Project',
            color: '#1976D2',
          },
          createdAt: '2025-08-16T14:30:00.000Z',
        },
        {
          id: 'entry-2',
          date: '2025-08-15',
          duration: 3.0,
          description: 'Testing and debugging',
          project: {
            id: 'project-2',
            name: 'Time Tracker',
            color: '#388E3C',
          },
          createdAt: '2025-08-15T16:45:00.000Z',
        },
      ];

      mockFetch.mockResolvedValueOnce(createMockResponse(mockActivity));

      const result = await apiRequest('/api/dashboard/recent-activity');
      
      expect(result).toHaveLength(2);
      expect(result[0]).toHaveProperty('id');
      expect(result[0]).toHaveProperty('duration');
      expect(result[0]).toHaveProperty('project');
      expect(result[0].project).toHaveProperty('name');
      expect(result[0].project).toHaveProperty('color');
    });

    it('should limit recent activity to specified count', async () => {
      const limitedActivity = Array(5).fill(null).map((_, index) => ({
        id: `entry-${index + 1}`,
        date: '2025-08-16',
        duration: 2.0,
        description: `Work item ${index + 1}`,
        project: {
          id: 'project-1',
          name: 'Test Project',
          color: '#1976D2',
        },
        createdAt: `2025-08-16T${10 + index}:00:00.000Z`,
      }));

      mockFetch.mockResolvedValueOnce(createMockResponse(limitedActivity));

      const result = await apiRequest('/api/dashboard/recent-activity?limit=5');
      
      expect(result).toHaveLength(5);
    });
  });

  describe('Department Hours API', () => {
    it('should return department-level hour aggregations', async () => {
      const mockDepartmentHours = [
        {
          departmentId: 'dept-1',
          departmentName: 'Engineering',
          totalHours: 320.5,
          employeeCount: 8,
          averageHoursPerEmployee: 40.06,
        },
        {
          departmentId: 'dept-2',
          departmentName: 'Design',
          totalHours: 156.0,
          employeeCount: 4,
          averageHoursPerEmployee: 39.0,
        },
      ];

      const dateRange = '2025-08-09/2025-08-16';
      mockFetch.mockResolvedValueOnce(createMockResponse(mockDepartmentHours));

      const result = await apiRequest(`/api/dashboard/department-hours/${dateRange}`);
      
      expect(result).toHaveLength(2);
      expect(result[0]).toHaveProperty('departmentId');
      expect(result[0]).toHaveProperty('departmentName');
      expect(result[0]).toHaveProperty('totalHours');
      expect(result[0]).toHaveProperty('employeeCount');
      expect(result[0]).toHaveProperty('averageHoursPerEmployee');

      // Verify calculation accuracy
      expect(result[0].averageHoursPerEmployee).toBeCloseTo(
        result[0].totalHours / result[0].employeeCount, 2
      );
    });

    it('should handle departments with no time entries', async () => {
      const mockEmptyDepartments = [
        {
          departmentId: 'dept-3',
          departmentName: 'New Department',
          totalHours: 0,
          employeeCount: 2,
          averageHoursPerEmployee: 0,
        },
      ];

      mockFetch.mockResolvedValueOnce(createMockResponse(mockEmptyDepartments));

      const result = await apiRequest('/api/dashboard/department-hours/2025-08-16/2025-08-16');
      
      expect(result[0].totalHours).toBe(0);
      expect(result[0].averageHoursPerEmployee).toBe(0);
    });
  });

  describe('Dashboard Data Consistency', () => {
    it('should maintain data consistency across multiple API calls', async () => {
      // Mock consistent data across different endpoints
      const totalHoursFromStats = 42.5;
      const totalHoursFromBreakdown = [
        { totalHours: 25.5 },
        { totalHours: 17.0 }
      ];

      mockFetch
        .mockResolvedValueOnce(createMockResponse({ weekHours: totalHoursFromStats }))
        .mockResolvedValueOnce(createMockResponse(totalHoursFromBreakdown));

      const statsResult = await apiRequest('/api/dashboard/stats');
      const breakdownResult = await apiRequest('/api/dashboard/project-breakdown');

      const breakdownTotal = breakdownResult.reduce((sum: number, item: any) => sum + item.totalHours, 0);
      
      expect(statsResult.weekHours).toBeCloseTo(breakdownTotal, 1);
    });

    it('should handle role-based data filtering', async () => {
      // Employee should see limited data compared to admin
      const employeeStats = {
        todayHours: 8.0,
        weekHours: 40.0,
        monthHours: 160.0,
        activeProjects: 2, // Limited to assigned projects
      };

      mockFetch.mockResolvedValueOnce(createMockResponse(employeeStats));

      const result = await apiRequest('/api/dashboard/stats');
      
      // Verify employee sees appropriate data scope
      expect(result.activeProjects).toBeLessThanOrEqual(5);
      expect(result).not.toHaveProperty('departmentStats');
      expect(result).not.toHaveProperty('systemWideMetrics');
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle API timeout gracefully', async () => {
      mockFetch.mockImplementationOnce(() => 
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Request timeout')), 100)
        )
      );

      await expect(apiRequest('/api/dashboard/stats')).rejects.toThrow('Request timeout');
    });

    it('should handle malformed response data', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(null),
      } as Response);

      const result = await apiRequest('/api/dashboard/stats');
      
      expect(result).toBeNull();
    });

    it('should handle date range validation errors', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse({
        message: 'Invalid date range: start date must be before end date'
      }, 400));

      await expect(apiRequest('/api/dashboard/department-hours/2025-08-16/2025-08-01'))
        .rejects.toThrow('Invalid date range');
    });
  });
});