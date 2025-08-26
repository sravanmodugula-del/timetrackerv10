import { describe, it, expect } from 'vitest';
import { insertProjectSchema } from '../shared/schema';
import { z } from 'zod';

describe('Project Number Field Validation', () => {
  describe('Schema Validation', () => {
    it('should accept valid project data without project number', () => {
      const validProject = {
        name: 'Test Project',
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true,
        userId: 'test-user-id'
      };

      const result = insertProjectSchema.safeParse(validProject);
      if (!result.success) {
        console.log('Validation errors:', result.error.errors);
      }
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.name).toBe('Test Project');
        expect(result.data.projectNumber).toBeUndefined();
      }
    });

    it('should accept valid project data with project number', () => {
      const validProject = {
        name: 'Test Project with Number',
        projectNumber: 'PRJ-001',
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true
      };

      const result = insertProjectSchema.safeParse(validProject);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.name).toBe('Test Project with Number');
        expect(result.data.projectNumber).toBe('PRJ-001');
      }
    });

    it('should accept various project number formats', () => {
      const validFormats = [
        'PRJ-001',
        '2024-WEB-001',
        'ABC123',
        'PROJECT_001',
        'P1',
        'WEB-DEV-2024',
        '123-ABC-XYZ',
        'PROJ2024'
      ];

      validFormats.forEach(projectNumber => {
        const project = {
          name: `Test Project ${projectNumber}`,
          projectNumber,
          description: 'Test Description',
          color: '#1976D2',
          isEnterpriseWide: true
        };

        const result = insertProjectSchema.safeParse(project);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.projectNumber).toBe(projectNumber);
        }
      });
    });

    it('should accept empty string as project number', () => {
      const project = {
        name: 'Test Project Empty',
        projectNumber: '',
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true
      };

      const result = insertProjectSchema.safeParse(project);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.projectNumber).toBe('');
      }
    });

    it('should accept null as project number', () => {
      const project = {
        name: 'Test Project Null',
        projectNumber: null,
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true
      };

      const result = insertProjectSchema.safeParse(project);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.projectNumber).toBeNull();
      }
    });

    it('should validate project number is optional', () => {
      // Test that project number is truly optional by omitting it
      const projectWithoutNumber = {
        name: 'Test Project No Number',
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true
      };

      const result = insertProjectSchema.safeParse(projectWithoutNumber);
      expect(result.success).toBe(true);
    });

    it('should still require other mandatory fields', () => {
      // Test that adding project number doesn't break other validations
      const invalidProject = {
        projectNumber: 'PRJ-001',
        description: 'Test Description',
        color: '#1976D2',
        isEnterpriseWide: true
        // Missing required 'name' field
      };

      const result = insertProjectSchema.safeParse(invalidProject);
      expect(result.success).toBe(false);
    });
  });

  describe('Project Number Format Testing', () => {
    it('should handle special characters in project numbers', () => {
      const specialCharFormats = [
        'PRJ-001',
        'PRJ_001',
        'PRJ.001',
        'PRJ/001',
        'PRJ#001',
        'PRJ@001'
      ];

      specialCharFormats.forEach(projectNumber => {
        const project = {
          name: 'Test Project',
          projectNumber,
          color: '#1976D2',
          isEnterpriseWide: true
        };

        const result = insertProjectSchema.safeParse(project);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.projectNumber).toBe(projectNumber);
        }
      });
    });

    it('should handle numeric-only project numbers', () => {
      const numericFormats = [
        '001',
        '12345',
        '2024',
        '999999'
      ];

      numericFormats.forEach(projectNumber => {
        const project = {
          name: 'Test Project',
          projectNumber,
          color: '#1976D2',
          isEnterpriseWide: true
        };

        const result = insertProjectSchema.safeParse(project);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.projectNumber).toBe(projectNumber);
        }
      });
    });

    it('should handle long project numbers', () => {
      const longProjectNumber = 'A'.repeat(50); // Max expected length
      
      const project = {
        name: 'Test Project Long Number',
        projectNumber: longProjectNumber,
        color: '#1976D2',
        isEnterpriseWide: true
      };

      const result = insertProjectSchema.safeParse(project);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.projectNumber).toBe(longProjectNumber);
        expect(result.data.projectNumber.length).toBe(50);
      }
    });
  });

  describe('Form Schema Integration', () => {
    it('should work with form extensions', () => {
      // Test that the schema works with typical form extensions
      const formSchema = insertProjectSchema.omit({ userId: true }).extend({
        assignedEmployeeIds: z.array(z.string()).optional(),
        startDate: z.string().optional(),
        endDate: z.string().optional(),
        projectNumber: z.string().optional(),
      });

      const formData = {
        name: 'Form Test Project',
        projectNumber: 'FORM-001',
        description: 'Form test',
        color: '#1976D2',
        isEnterpriseWide: true,
        assignedEmployeeIds: ['emp1', 'emp2'],
        startDate: '2024-01-01',
        endDate: '2024-12-31'
      };

      const result = formSchema.safeParse(formData);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.projectNumber).toBe('FORM-001');
        expect(result.data.assignedEmployeeIds).toEqual(['emp1', 'emp2']);
      }
    });
  });
});