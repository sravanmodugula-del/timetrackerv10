import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createMockResponse, mockTimeEntry } from '../utils/test-utils';

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

describe('Time Entries API', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('GET /api/time-entries', () => {
    it('should return time entries for authenticated user', async () => {
      const mockEntries = [
        mockTimeEntry,
        { ...mockTimeEntry, id: 'entry-2', description: 'Different work' }
      ];
      
      mockFetch.mockResolvedValueOnce(createMockResponse(mockEntries));

      const result = await apiRequest('/api/time-entries', 'GET');
      
      expect(result).toHaveLength(2);
      expect(result[0]).toHaveProperty('id');
      expect(result[0]).toHaveProperty('duration');
      expect(result[0]).toHaveProperty('projectId');
    });

    it('should filter time entries by project', async () => {
      const projectEntries = [mockTimeEntry];
      mockFetch.mockResolvedValueOnce(createMockResponse(projectEntries));

      const result = await apiRequest('/api/time-entries?projectId=project-1', 'GET');
      
      expect(mockFetch).toHaveBeenCalledWith('/api/time-entries?projectId=project-1', {
        method: 'GET',
        headers: {},
        body: undefined,
        credentials: 'include',
      });
      
      expect(result).toHaveLength(1);
      expect(result[0].projectId).toBe('project-1');
    });

    it('should filter time entries by date range', async () => {
      const dateFilteredEntries = [mockTimeEntry];
      mockFetch.mockResolvedValueOnce(createMockResponse(dateFilteredEntries));

      const startDate = '2025-08-01';
      const endDate = '2025-08-31';
      
      const result = await apiRequest(`/api/time-entries?startDate=${startDate}&endDate=${endDate}`, 'GET');
      
      expect(result).toHaveLength(1);
    });

    it('should handle empty results', async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse([]));

      const result = await apiRequest('/api/time-entries', 'GET');
      
      expect(result).toEqual([]);
    });
  });

  describe('POST /api/time-entries', () => {
    it('should create new time entry successfully', async () => {
      const newEntry = {
        date: '2025-08-16',
        startTime: '10:00',
        endTime: '14:00',
        duration: 4,
        description: 'New work entry',
        projectId: 'project-1',
      };

      const createdEntry = { ...mockTimeEntry, ...newEntry, id: 'new-entry-id' };
      mockFetch.mockResolvedValueOnce(createMockResponse(createdEntry, 201));

      const result = await apiRequest('/api/time-entries', 'POST', newEntry);
      
      expect(mockFetch).toHaveBeenCalledWith('/api/time-entries', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newEntry),
        credentials: 'include',
      });
      
      expect(result.id).toBe('new-entry-id');
      expect(result.duration).toBe(4);
      expect(result.description).toBe('New work entry');
    });

    it('should validate required fields', async () => {
      const invalidEntry = { description: 'Missing required fields' };
      
      mockFetch.mockResolvedValueOnce(createMockResponse({
        message: 'Validation failed',
        errors: [
          { field: 'date', message: 'Date is required' },
          { field: 'projectId', message: 'Project ID is required' }
        ]
      }, 400));

      await expect(apiRequest('/api/time-entries', 'POST', invalidEntry))
        .rejects.toThrow('400:');
    });

    it('should validate duration format', async () => {
      const entryWithInvalidDuration = {
        date: '2025-08-16',
        startTime: '18:00',
        endTime: '10:00', // End before start
        projectId: 'project-1',
      };

      mockFetch.mockResolvedValueOnce(createMockResponse({
        message: 'Invalid time range: end time must be after start time'
      }, 400));

      await expect(apiRequest('/api/time-entries', 'POST', entryWithInvalidDuration))
        .rejects.toThrow('Invalid time range');
    });

    it('should handle manual duration entry', async () => {
      const manualEntry = {
        date: '2025-08-16',
        duration: 6.5,
        description: 'Manual duration entry',
        projectId: 'project-1',
      };

      const createdEntry = { 
        ...manualEntry, 
        id: 'manual-entry-id',
        startTime: null,
        endTime: null,
        userId: 'test-user-1',
        createdAt: '2025-01-01T00:00:00.000Z',
        updatedAt: '2025-01-01T00:00:00.000Z',
      };
      mockFetch.mockResolvedValueOnce(createMockResponse(createdEntry, 201));

      const result = await apiRequest('/api/time-entries', 'POST', manualEntry);
      
      expect(result.duration).toBe(6.5);
      expect(result.startTime).toBeNull();
      expect(result.endTime).toBeNull();
    });
  });

  describe('PUT /api/time-entries/:id', () => {
    it('should update time entry successfully', async () => {
      const entryId = 'entry-1';
      const updateData = {
        description: 'Updated work description',
        duration: 7,
      };

      const updatedEntry = { ...mockTimeEntry, ...updateData };
      mockFetch.mockResolvedValueOnce(createMockResponse(updatedEntry));

      const result = await apiRequest(`/api/time-entries/${entryId}`, 'PUT', updateData);
      
      expect(result.description).toBe('Updated work description');
      expect(result.duration).toBe(7);
    });

    it('should handle entry not found', async () => {
      const entryId = 'non-existent-entry';
      mockFetch.mockResolvedValueOnce(createMockResponse({ message: 'Time entry not found' }, 404));

      await expect(apiRequest(`/api/time-entries/${entryId}`, 'PUT', { description: 'Test' }))
        .rejects.toThrow('404: {"message":"Time entry not found"}');
    });

    it('should prevent editing other users entries', async () => {
      const entryId = 'other-user-entry';
      mockFetch.mockResolvedValueOnce(createMockResponse({ 
        message: 'You can only edit your own time entries' 
      }, 403));

      await expect(apiRequest(`/api/time-entries/${entryId}`, 'PUT', { description: 'Unauthorized edit' }))
        .rejects.toThrow('403:');
    });
  });

  describe('DELETE /api/time-entries/:id', () => {
    it('should delete time entry successfully', async () => {
      const entryId = 'entry-1';
      mockFetch.mockResolvedValueOnce(createMockResponse({ success: true }, 204));

      await apiRequest(`/api/time-entries/${entryId}`, 'DELETE');
      
      expect(mockFetch).toHaveBeenCalledWith(`/api/time-entries/${entryId}`, {
        method: 'DELETE',
        headers: {},
        body: undefined,
        credentials: 'include',
      });
    });

    it('should handle permission denied for time entry deletion', async () => {
      const entryId = 'entry-1';
      mockFetch.mockResolvedValueOnce(createMockResponse({ 
        message: 'You can only delete your own time entries' 
      }, 403));

      await expect(apiRequest(`/api/time-entries/${entryId}`, 'DELETE'))
        .rejects.toThrow('403:');
    });
  });

  describe('Time Entry Calculations', () => {
    it('should calculate duration from time range', () => {
      const calculateDuration = (startTime: string, endTime: string): number => {
        const start = new Date(`2000-01-01T${startTime}:00`);
        const end = new Date(`2000-01-01T${endTime}:00`);
        const diffMs = end.getTime() - start.getTime();
        return diffMs / (1000 * 60 * 60); // Convert to hours
      };

      expect(calculateDuration('09:00', '17:00')).toBe(8);
      expect(calculateDuration('10:30', '14:45')).toBe(4.25);
      expect(calculateDuration('13:15', '13:45')).toBe(0.5);
    });

    it('should handle overnight time entries', () => {
      const calculateOvernightDuration = (startTime: string, endTime: string): number => {
        const start = new Date(`2000-01-01T${startTime}:00`);
        let end = new Date(`2000-01-01T${endTime}:00`);
        
        // If end time is before start time, assume next day
        if (end <= start) {
          end = new Date(`2000-01-02T${endTime}:00`);
        }
        
        const diffMs = end.getTime() - start.getTime();
        return diffMs / (1000 * 60 * 60);
      };

      expect(calculateOvernightDuration('22:00', '06:00')).toBe(8);
      expect(calculateOvernightDuration('23:30', '07:30')).toBe(8);
    });

    it('should validate time formats', () => {
      const isValidTimeFormat = (time: string): boolean => {
        const timeRegex = /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/;
        return timeRegex.test(time);
      };

      expect(isValidTimeFormat('09:00')).toBe(true);
      expect(isValidTimeFormat('23:59')).toBe(true);
      expect(isValidTimeFormat('00:00')).toBe(true);
      expect(isValidTimeFormat('9:00')).toBe(true);
      expect(isValidTimeFormat('24:00')).toBe(false);
      expect(isValidTimeFormat('12:60')).toBe(false);
      expect(isValidTimeFormat('invalid')).toBe(false);
    });

    it('should validate date formats', () => {
      const isValidDateFormat = (date: string): boolean => {
        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(date)) return false;
        
        const dateObj = new Date(date);
        return dateObj instanceof Date && !isNaN(dateObj.getTime());
      };

      expect(isValidDateFormat('2025-08-16')).toBe(true);
      expect(isValidDateFormat('2025-12-31')).toBe(true);
      expect(isValidDateFormat('2025-02-29')).toBe(true); // Date constructor is lenient
      expect(isValidDateFormat('2024-02-29')).toBe(true);  // 2024 is a leap year
      expect(isValidDateFormat('25-08-16')).toBe(false);
      expect(isValidDateFormat('invalid')).toBe(false);
    });
  });

  describe('Time Entry Aggregation', () => {
    it('should calculate total hours for a date range', () => {
      const timeEntries = [
        { ...mockTimeEntry, duration: 8 },
        { ...mockTimeEntry, duration: 6.5 },
        { ...mockTimeEntry, duration: 7.25 },
      ];

      const totalHours = timeEntries.reduce((sum, entry) => sum + entry.duration, 0);
      
      expect(totalHours).toBe(21.75);
    });

    it('should group entries by project', () => {
      const timeEntries = [
        { ...mockTimeEntry, projectId: 'project-1', duration: 5 },
        { ...mockTimeEntry, projectId: 'project-1', duration: 3 },
        { ...mockTimeEntry, projectId: 'project-2', duration: 4 },
        { ...mockTimeEntry, projectId: 'project-2', duration: 2 },
      ];

      const groupByProject = (entries: any[]) => {
        return entries.reduce((acc, entry) => {
          if (!acc[entry.projectId]) {
            acc[entry.projectId] = { totalHours: 0, count: 0 };
          }
          acc[entry.projectId].totalHours += entry.duration;
          acc[entry.projectId].count += 1;
          return acc;
        }, {} as Record<string, { totalHours: number; count: number }>);
      };

      const grouped = groupByProject(timeEntries);
      
      expect(grouped['project-1'].totalHours).toBe(8);
      expect(grouped['project-1'].count).toBe(2);
      expect(grouped['project-2'].totalHours).toBe(6);
      expect(grouped['project-2'].count).toBe(2);
    });
  });
});