import React from 'react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Projects from '../client/src/pages/projects';

// Mock the API and authentication
vi.mock('../client/src/hooks/useAuth', () => ({
  useAuth: () => ({
    isAuthenticated: true,
    isLoading: false,
    role: 'admin',
    user: { id: 'test-user', email: 'test@example.com' }
  })
}));

vi.mock('../client/src/hooks/usePermissions', () => ({
  usePermissions: () => ({
    canCreateProjects: true,
    canEditProjects: true,
    canDeleteProjects: true,
    canViewProjects: true
  })
}));

vi.mock('../client/src/lib/queryClient', () => ({
  apiRequest: vi.fn(),
}));

// Mock react-query
const createTestQueryClient = () => new QueryClient({
  defaultOptions: {
    queries: { retry: false },
    mutations: { retry: false },
  },
});

const renderWithProviders = (component: React.ReactElement) => {
  const queryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      {component}
    </QueryClientProvider>
  );
};

describe('Project Form with Project Number', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Project Creation Form', () => {
    it('should render project number field in create form', async () => {
      renderWithProviders(<Projects />);
      
      // Click new project button
      const newProjectButton = screen.getByText('New Project');
      await userEvent.click(newProjectButton);

      // Check if project number field exists
      const projectNumberInput = screen.getByLabelText('Project Number (optional)');
      expect(projectNumberInput).toBeInTheDocument();
      expect(projectNumberInput).toHaveAttribute('placeholder', 'e.g., PRJ-001, 2024-001, etc.');
    });

    it('should allow entering project number', async () => {
      renderWithProviders(<Projects />);
      
      // Open create form
      const newProjectButton = screen.getByText('New Project');
      await userEvent.click(newProjectButton);

      // Enter project number
      const projectNumberInput = screen.getByLabelText('Project Number (optional)');
      await userEvent.type(projectNumberInput, 'PRJ-001');

      expect(projectNumberInput).toHaveValue('PRJ-001');
    });

    it('should validate alphanumeric project numbers', async () => {
      renderWithProviders(<Projects />);
      
      // Open create form
      const newProjectButton = screen.getByText('New Project');
      await userEvent.click(newProjectButton);

      const projectNumberInput = screen.getByLabelText('Project Number (optional)');
      
      // Test various valid formats
      const validNumbers = ['PRJ-001', '2024-WEB-001', 'ABC123', 'PROJECT_001'];
      
      for (const number of validNumbers) {
        await userEvent.clear(projectNumberInput);
        await userEvent.type(projectNumberInput, number);
        expect(projectNumberInput).toHaveValue(number);
      }
    });

    it('should submit form with project number', async () => {
      const mockApiRequest = vi.fn().mockResolvedValue({
        json: () => Promise.resolve({
          id: 'new-project-id',
          name: 'Test Project',
          projectNumber: 'PRJ-001'
        })
      });
      
      vi.mocked(require('../client/src/lib/queryClient').apiRequest).mockImplementation(mockApiRequest);

      renderWithProviders(<Projects />);
      
      // Open create form
      const newProjectButton = screen.getByText('New Project');
      await userEvent.click(newProjectButton);

      // Fill form
      await userEvent.type(screen.getByLabelText('Project Name'), 'Test Project');
      await userEvent.type(screen.getByLabelText('Project Number (optional)'), 'PRJ-001');
      
      // Submit form
      const submitButton = screen.getByText('Create Project');
      await userEvent.click(submitButton);

      await waitFor(() => {
        expect(mockApiRequest).toHaveBeenCalledWith('POST', '/api/projects', 
          expect.objectContaining({
            name: 'Test Project',
            projectNumber: 'PRJ-001'
          })
        );
      });
    });

    it('should submit form without project number', async () => {
      const mockApiRequest = vi.fn().mockResolvedValue({
        json: () => Promise.resolve({
          id: 'new-project-id',
          name: 'Test Project',
          projectNumber: null
        })
      });
      
      vi.mocked(require('../client/src/lib/queryClient').apiRequest).mockImplementation(mockApiRequest);

      renderWithProviders(<Projects />);
      
      // Open create form
      const newProjectButton = screen.getByText('New Project');
      await userEvent.click(newProjectButton);

      // Fill form (leaving project number empty)
      await userEvent.type(screen.getByLabelText('Project Name'), 'Test Project');
      
      // Submit form
      const submitButton = screen.getByText('Create Project');
      await userEvent.click(submitButton);

      await waitFor(() => {
        expect(mockApiRequest).toHaveBeenCalledWith('POST', '/api/projects', 
          expect.objectContaining({
            name: 'Test Project',
            projectNumber: ''
          })
        );
      });
    });
  });

  describe('Project Edit Form', () => {
    const mockProject = {
      id: 'test-project-id',
      name: 'Existing Project',
      projectNumber: 'PRJ-001',
      description: 'Test description',
      color: '#1976D2',
      isEnterpriseWide: true,
      userId: 'test-user',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    it('should populate project number in edit form', async () => {
      // Mock the projects query to return test project
      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], [mockProject]);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Find and click edit button
      const editButton = screen.getByRole('button', { name: /edit/i });
      await userEvent.click(editButton);

      // Check if project number is populated
      const projectNumberInput = screen.getByLabelText('Project Number (optional)');
      expect(projectNumberInput).toHaveValue('PRJ-001');
    });

    it('should update project number', async () => {
      const mockApiRequest = vi.fn().mockResolvedValue({
        json: () => Promise.resolve({
          ...mockProject,
          projectNumber: 'PRJ-002'
        })
      });
      
      vi.mocked(require('../client/src/lib/queryClient').apiRequest).mockImplementation(mockApiRequest);

      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], [mockProject]);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Open edit form
      const editButton = screen.getByRole('button', { name: /edit/i });
      await userEvent.click(editButton);

      // Update project number
      const projectNumberInput = screen.getByLabelText('Project Number (optional)');
      await userEvent.clear(projectNumberInput);
      await userEvent.type(projectNumberInput, 'PRJ-002');

      // Submit form
      const submitButton = screen.getByText('Update Project');
      await userEvent.click(submitButton);

      await waitFor(() => {
        expect(mockApiRequest).toHaveBeenCalledWith('PUT', `/api/projects/${mockProject.id}`, 
          expect.objectContaining({
            projectNumber: 'PRJ-002'
          })
        );
      });
    });

    it('should handle project without project number', async () => {
      const projectWithoutNumber = {
        ...mockProject,
        projectNumber: null
      };

      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], [projectWithoutNumber]);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Open edit form
      const editButton = screen.getByRole('button', { name: /edit/i });
      await userEvent.click(editButton);

      // Check if project number field is empty
      const projectNumberInput = screen.getByLabelText('Project Number (optional)');
      expect(projectNumberInput).toHaveValue('');
    });
  });

  describe('Form Reset Functionality', () => {
    it('should reset project number when closing dialog', async () => {
      renderWithProviders(<Projects />);
      
      // Open create form
      const newProjectButton = screen.getByText('New Project');
      await userEvent.click(newProjectButton);

      // Enter project number
      const projectNumberInput = screen.getByLabelText('Project Number (optional)');
      await userEvent.type(projectNumberInput, 'PRJ-001');

      // Close dialog
      const cancelButton = screen.getByText('Cancel');
      await userEvent.click(cancelButton);

      // Reopen dialog and check if field is reset
      await userEvent.click(newProjectButton);
      const newProjectNumberInput = screen.getByLabelText('Project Number (optional)');
      expect(newProjectNumberInput).toHaveValue('');
    });

    it('should reset form after successful creation', async () => {
      const mockApiRequest = vi.fn().mockResolvedValue({
        json: () => Promise.resolve({
          id: 'new-project-id',
          name: 'Test Project',
          projectNumber: 'PRJ-001'
        })
      });
      
      vi.mocked(require('../client/src/lib/queryClient').apiRequest).mockImplementation(mockApiRequest);

      renderWithProviders(<Projects />);
      
      // Create project
      const newProjectButton = screen.getByText('New Project');
      await userEvent.click(newProjectButton);

      await userEvent.type(screen.getByLabelText('Project Name'), 'Test Project');
      await userEvent.type(screen.getByLabelText('Project Number (optional)'), 'PRJ-001');
      
      const submitButton = screen.getByText('Create Project');
      await userEvent.click(submitButton);

      // Wait for success and dialog to close, then reopen
      await waitFor(() => {
        expect(screen.queryByText('Create New Project')).not.toBeInTheDocument();
      });

      await userEvent.click(newProjectButton);
      
      // Check if form is reset
      const projectNumberInput = screen.getByLabelText('Project Number (optional)');
      expect(projectNumberInput).toHaveValue('');
    });
  });
});