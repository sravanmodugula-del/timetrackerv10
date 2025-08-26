import { describe, it, expect } from 'vitest';

// Date utility functions to test
const formatDateForDisplay = (date: string | Date): string => {
  const dateObj = date instanceof Date ? date : new Date(date);
  return dateObj.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
};

const calculateDuration = (startTime: string, endTime: string): number => {
  const start = new Date(`2000-01-01T${startTime}:00`);
  const end = new Date(`2000-01-01T${endTime}:00`);
  const diffMs = end.getTime() - start.getTime();
  return diffMs / (1000 * 60 * 60); // Convert to hours
};

const isWeekend = (date: string | Date): boolean => {
  const dateObj = date instanceof Date ? date : new Date(date);
  const day = dateObj.getDay();
  return day === 0 || day === 6; // Sunday or Saturday
};

const getWeekStart = (date: string | Date): Date => {
  const dateObj = date instanceof Date ? date : new Date(date);
  const day = dateObj.getDay();
  const diff = dateObj.getDate() - day;
  return new Date(dateObj.setDate(diff));
};

const getDaysInMonth = (year: number, month: number): number => {
  return new Date(year, month, 0).getDate();
};

describe('Date Utilities', () => {
  describe('formatDateForDisplay', () => {
    it('should format date string correctly', () => {
      const result = formatDateForDisplay('2025-08-16');
      expect(result).toBe('Aug 16, 2025');
    });

    it('should format Date object correctly', () => {
      const date = new Date('2025-12-25');
      const result = formatDateForDisplay(date);
      expect(result).toBe('Dec 25, 2025');
    });

    it('should handle edge case dates', () => {
      expect(formatDateForDisplay('2025-01-01')).toBe('Jan 1, 2025');
      expect(formatDateForDisplay('2025-12-31')).toBe('Dec 31, 2025');
    });
  });

  describe('calculateDuration', () => {
    it('should calculate standard work day', () => {
      expect(calculateDuration('09:00', '17:00')).toBe(8);
    });

    it('should calculate partial hours', () => {
      expect(calculateDuration('10:30', '14:45')).toBe(4.25);
    });

    it('should calculate short durations', () => {
      expect(calculateDuration('13:00', '13:30')).toBe(0.5);
    });

    it('should handle same start and end time', () => {
      expect(calculateDuration('12:00', '12:00')).toBe(0);
    });

    it('should calculate lunch hour', () => {
      expect(calculateDuration('12:00', '13:00')).toBe(1);
    });
  });

  describe('isWeekend', () => {
    it('should identify Saturday as weekend', () => {
      const saturday = '2025-08-16'; // This is a Saturday
      expect(isWeekend(saturday)).toBe(true);
    });

    it('should identify Sunday as weekend', () => {
      const sunday = '2025-08-17'; // This is a Sunday
      expect(isWeekend(sunday)).toBe(true);
    });

    it('should identify weekday as not weekend', () => {
      const monday = '2025-08-18'; // This is a Monday
      expect(isWeekend(monday)).toBe(false);
    });

    it('should handle Date objects', () => {
      const saturday = new Date('2025-08-16');
      expect(isWeekend(saturday)).toBe(true);
    });
  });

  describe('getWeekStart', () => {
    it('should get Sunday as start of week', () => {
      const thursday = new Date('2025-08-14'); // Thursday
      const weekStart = getWeekStart(thursday);
      expect(weekStart.getDay()).toBe(0); // Sunday
    });

    it('should handle Sunday as input', () => {
      const sunday = new Date('2025-08-17');
      const weekStart = getWeekStart(sunday);
      expect(weekStart.getDay()).toBe(0); // Should still be Sunday
    });

    it('should handle Monday as input', () => {
      const monday = new Date('2025-08-18');
      const weekStart = getWeekStart(monday);
      expect(weekStart.getDay()).toBe(0); // Should be previous Sunday
    });
  });

  describe('getDaysInMonth', () => {
    it('should return correct days for regular months', () => {
      expect(getDaysInMonth(2025, 1)).toBe(31); // January
      expect(getDaysInMonth(2025, 4)).toBe(30); // April
      expect(getDaysInMonth(2025, 6)).toBe(30); // June
      expect(getDaysInMonth(2025, 12)).toBe(31); // December
    });

    it('should handle February in regular year', () => {
      expect(getDaysInMonth(2025, 2)).toBe(28); // February 2025 (not leap year)
    });

    it('should handle February in leap year', () => {
      expect(getDaysInMonth(2024, 2)).toBe(29); // February 2024 (leap year)
    });

    it('should handle February in century years', () => {
      expect(getDaysInMonth(1900, 2)).toBe(28); // 1900 is not a leap year
      expect(getDaysInMonth(2000, 2)).toBe(29); // 2000 is a leap year
    });
  });
});