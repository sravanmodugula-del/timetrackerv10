import { describe, it, expect } from 'vitest';

describe('Project Number Utility Functions', () => {
  describe('Project Number Formatting', () => {
    it('should format project number display correctly', () => {
      const formatProjectNumber = (projectNumber: string | null) => {
        return projectNumber && projectNumber.trim() !== '' ? `#${projectNumber}` : null;
      };

      expect(formatProjectNumber('PRJ-001')).toBe('#PRJ-001');
      expect(formatProjectNumber('2024-WEB-001')).toBe('#2024-WEB-001');
      expect(formatProjectNumber('')).toBeNull();
      expect(formatProjectNumber(null)).toBeNull();
    });

    it('should validate project number formats', () => {
      const isValidProjectNumber = (projectNumber: string) => {
        // Basic validation: alphanumeric with common separators, max 50 chars
        if (!projectNumber || projectNumber.length > 50) return false;
        return /^[A-Za-z0-9\-_./#+@]*$/.test(projectNumber);
      };

      // Valid formats
      expect(isValidProjectNumber('PRJ-001')).toBe(true);
      expect(isValidProjectNumber('2024-WEB-001')).toBe(true);
      expect(isValidProjectNumber('ABC123')).toBe(true);
      expect(isValidProjectNumber('PROJECT_001')).toBe(true);
      expect(isValidProjectNumber('PRJ.001')).toBe(true);
      expect(isValidProjectNumber('PRJ#001')).toBe(true);
      expect(isValidProjectNumber('PRJ@001')).toBe(true);

      // Invalid formats
      expect(isValidProjectNumber('A'.repeat(51))).toBe(false); // Too long
      expect(isValidProjectNumber('')).toBe(false); // Empty
    });

    it('should generate unique project numbers', () => {
      const generateProjectNumber = (prefix: string, counter: number) => {
        return `${prefix}-${counter.toString().padStart(3, '0')}`;
      };

      expect(generateProjectNumber('PRJ', 1)).toBe('PRJ-001');
      expect(generateProjectNumber('PRJ', 999)).toBe('PRJ-999');
      expect(generateProjectNumber('WEB', 42)).toBe('WEB-042');
    });
  });

  describe('Project Search and Filtering', () => {
    const mockProjects = [
      { id: '1', name: 'Alpha Project', projectNumber: 'PRJ-001' },
      { id: '2', name: 'Beta Project', projectNumber: '2024-001' },
      { id: '3', name: 'Gamma Project', projectNumber: null },
      { id: '4', name: 'Delta Project', projectNumber: 'WEB-001' }
    ];

    it('should filter projects by project number', () => {
      const filterByProjectNumber = (projects: typeof mockProjects, searchTerm: string) => {
        return projects.filter(project => 
          project.projectNumber?.toLowerCase().includes(searchTerm.toLowerCase())
        );
      };

      const results = filterByProjectNumber(mockProjects, 'PRJ');
      expect(results).toHaveLength(1);
      expect(results[0].projectNumber).toBe('PRJ-001');
    });

    it('should search projects by name or project number', () => {
      const searchProjects = (projects: typeof mockProjects, searchTerm: string) => {
        return projects.filter(project => 
          project.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          project.projectNumber?.toLowerCase().includes(searchTerm.toLowerCase())
        );
      };

      const alphaResults = searchProjects(mockProjects, 'alpha');
      expect(alphaResults).toHaveLength(1);
      expect(alphaResults[0].name).toBe('Alpha Project');

      const prjResults = searchProjects(mockProjects, 'prj');
      expect(prjResults).toHaveLength(1);
      expect(prjResults[0].projectNumber).toBe('PRJ-001');

      const webResults = searchProjects(mockProjects, 'web');
      expect(webResults).toHaveLength(1);
      expect(webResults[0].projectNumber).toBe('WEB-001');
    });

    it('should sort projects with project numbers first', () => {
      const sortProjectsWithNumbersFirst = (projects: typeof mockProjects) => {
        return [...projects].sort((a, b) => {
          // Projects with numbers come first
          if (a.projectNumber && !b.projectNumber) return -1;
          if (!a.projectNumber && b.projectNumber) return 1;
          
          // Both have numbers, sort by project number
          if (a.projectNumber && b.projectNumber) {
            return a.projectNumber.localeCompare(b.projectNumber);
          }
          
          // Neither has numbers, sort by name
          return a.name.localeCompare(b.name);
        });
      };

      const sorted = sortProjectsWithNumbersFirst(mockProjects);
      expect(sorted[0].projectNumber).toBe('2024-001');
      expect(sorted[1].projectNumber).toBe('PRJ-001');
      expect(sorted[2].projectNumber).toBe('WEB-001');
      expect(sorted[3].projectNumber).toBeNull();
    });
  });

  describe('Project Number Validation Helpers', () => {
    it('should check for duplicate project numbers', () => {
      const checkDuplicateProjectNumber = (
        projects: Array<{projectNumber: string | null}>, 
        newProjectNumber: string,
        excludeId?: string
      ) => {
        return projects.some(project => 
          project.projectNumber === newProjectNumber
        );
      };

      const projects = [
        { id: '1', projectNumber: 'PRJ-001' },
        { id: '2', projectNumber: 'PRJ-002' },
        { id: '3', projectNumber: null }
      ];

      expect(checkDuplicateProjectNumber(projects, 'PRJ-001')).toBe(true);
      expect(checkDuplicateProjectNumber(projects, 'PRJ-003')).toBe(false);
      expect(checkDuplicateProjectNumber(projects, '')).toBe(false);
    });

    it('should suggest next available project number', () => {
      const suggestNextProjectNumber = (
        projects: Array<{projectNumber: string | null}>,
        prefix: string = 'PRJ'
      ) => {
        const existingNumbers = projects
          .map(p => p.projectNumber)
          .filter(num => num?.startsWith(`${prefix}-`))
          .map(num => parseInt(num!.split('-')[1]))
          .filter(num => !isNaN(num));

        const maxNumber = Math.max(0, ...existingNumbers);
        return `${prefix}-${(maxNumber + 1).toString().padStart(3, '0')}`;
      };

      const projects = [
        { projectNumber: 'PRJ-001' },
        { projectNumber: 'PRJ-003' },
        { projectNumber: 'WEB-001' },
        { projectNumber: null }
      ];

      expect(suggestNextProjectNumber(projects, 'PRJ')).toBe('PRJ-004');
      expect(suggestNextProjectNumber(projects, 'WEB')).toBe('WEB-002');
      expect(suggestNextProjectNumber(projects, 'NEW')).toBe('NEW-001');
    });
  });
});