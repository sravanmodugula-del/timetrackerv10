/**
 * Component Verification Tests for Employee Assignment UI
 * Tests that UI components exist and render correctly for different roles
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Projects from '../client/src/pages/projects';
import { useAuth } from '../client/src/hooks/useAuth';
import { usePermissions } from '../client/src/hooks/usePermissions';

// Mock the hooks
vi.mock('../client/src/hooks/useAuth');
vi.mock('../client/src/hooks/usePermissions');
vi.mock('../client/src/hooks/useRole');

const mockUseAuth = useAuth as jest.MockedFunction<typeof useAuth>;
const mockUsePermissions = usePermissions as jest.MockedFunction<typeof usePermissions>;

// Mock fetch for API calls
global.fetch = vi.fn();

describe('Employee Assignment UI Verification', () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    });
    vi.clearAllMocks();
  });

  const renderWithProviders = (component: React.ReactElement) => {
    return render(
      <QueryClientProvider client={queryClient}>
        {component}
      </QueryClientProvider>
    );
  };

  describe('Admin Role UI Elements', () => {
    beforeEach(() => {
      mockUseAuth.mockReturnValue({
        user: { id: 'admin-id', email: 'admin@test.com', role: 'admin' },
        isAuthenticated: true,
        isLoading: false,
      });
      
      mockUsePermissions.mockReturnValue({
        canCreateProjects: true,
        canEditProjects: true,
        canDeleteProjects: true,
        canAssignEmployees: true,
        canViewAllProjects: true,
      });

      // Mock API responses
      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ([]), // projects
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ([
            { id: 'emp1', firstName: 'John', lastName: 'Doe', department: 'Engineering' },
            { id: 'emp2', firstName: 'Jane', lastName: 'Smith', department: 'Marketing' }
          ]), // employees
        });
    });

    it('should show New Project button for admin role', async () => {
      renderWithProviders(<Projects />);
      
      await waitFor(() => {
        expect(screen.getByTestId('button-new-project')).toBeInTheDocument();
      });
    });

    it('should show Assigned Employees tab when creating project', async () => {
      renderWithProviders(<Projects />);
      
      await waitFor(() => {
        const newProjectButton = screen.getByTestId('button-new-project');
        fireEvent.click(newProjectButton);
      });

      await waitFor(() => {
        expect(screen.getByTestId('tab-employees')).toBeInTheDocument();
      });
    });

    it('should show employee checkboxes when Assigned Employees tab is clicked', async () => {
      renderWithProviders(<Projects />);
      
      // Click New Project
      await waitFor(() => {
        const newProjectButton = screen.getByTestId('button-new-project');
        fireEvent.click(newProjectButton);
      });

      // Click Assigned Employees tab
      await waitFor(() => {
        const employeesTab = screen.getByTestId('tab-employees');
        fireEvent.click(employeesTab);
      });

      // Should see employee checkboxes
      await waitFor(() => {
        expect(screen.getByTestId('checkbox-employee-emp1')).toBeInTheDocument();
        expect(screen.getByTestId('checkbox-employee-emp2')).toBeInTheDocument();
      });
    });
  });

  describe('Project Manager Role UI Elements', () => {
    beforeEach(() => {
      mockUseAuth.mockReturnValue({
        user: { id: 'pm-id', email: 'pm@test.com', role: 'project_manager' },
        isAuthenticated: true,
        isLoading: false,
      });
      
      mockUsePermissions.mockReturnValue({
        canCreateProjects: true,
        canEditProjects: true,
        canDeleteProjects: false, // PM cannot delete
        canAssignEmployees: true,
        canViewAllProjects: true,
      });

      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ([]),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ([
            { id: 'emp1', firstName: 'John', lastName: 'Doe', department: 'Engineering' }
          ]),
        });
    });

    it('should show New Project button for project manager role', async () => {
      renderWithProviders(<Projects />);
      
      await waitFor(() => {
        expect(screen.getByTestId('button-new-project')).toBeInTheDocument();
      });
    });

    it('should show employee assignment capabilities for project manager', async () => {
      renderWithProviders(<Projects />);
      
      await waitFor(() => {
        const newProjectButton = screen.getByTestId('button-new-project');
        fireEvent.click(newProjectButton);
      });

      await waitFor(() => {
        expect(screen.getByTestId('tab-employees')).toBeInTheDocument();
      });
    });
  });

  describe('Manager Role UI Restrictions', () => {
    beforeEach(() => {
      mockUseAuth.mockReturnValue({
        user: { id: 'mgr-id', email: 'mgr@test.com', role: 'manager' },
        isAuthenticated: true,
        isLoading: false,
      });
      
      mockUsePermissions.mockReturnValue({
        canCreateProjects: false, // Manager cannot create
        canEditProjects: false,   // Manager cannot edit
        canDeleteProjects: false,
        canAssignEmployees: false,
        canViewAllProjects: true,
      });

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ([]),
      });
    });

    it('should NOT show New Project button for manager role', async () => {
      renderWithProviders(<Projects />);
      
      await waitFor(() => {
        expect(screen.queryByTestId('button-new-project')).not.toBeInTheDocument();
      });
    });
  });

  describe('Employee Role UI Restrictions', () => {
    beforeEach(() => {
      mockUseAuth.mockReturnValue({
        user: { id: 'emp-id', email: 'emp@test.com', role: 'employee' },
        isAuthenticated: true,
        isLoading: false,
      });
      
      mockUsePermissions.mockReturnValue({
        canCreateProjects: false,
        canEditProjects: false,
        canDeleteProjects: false,
        canAssignEmployees: false,
        canViewAllProjects: false, // Employee sees limited projects
      });

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ([]),
      });
    });

    it('should NOT show New Project button for employee role', async () => {
      renderWithProviders(<Projects />);
      
      await waitFor(() => {
        expect(screen.queryByTestId('button-new-project')).not.toBeInTheDocument();
      });
    });
  });
});