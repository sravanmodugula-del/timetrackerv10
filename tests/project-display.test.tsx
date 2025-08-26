import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
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

describe('Project Number Display', () => {
  const mockProjects = [
    {
      id: 'project-1',
      name: 'Project Alpha',
      projectNumber: 'PRJ-001',
      description: 'First project',
      color: '#1976D2',
      isEnterpriseWide: true,
      userId: 'test-user',
      createdAt: new Date(),
      updatedAt: new Date()
    },
    {
      id: 'project-2',
      name: 'Project Beta',
      projectNumber: '2024-WEB-001',
      description: 'Web project',
      color: '#388E3C',
      isEnterpriseWide: true,
      userId: 'test-user',
      createdAt: new Date(),
      updatedAt: new Date()
    },
    {
      id: 'project-3',
      name: 'Project Gamma',
      projectNumber: null,
      description: 'Project without number',
      color: '#F57C00',
      isEnterpriseWide: true,
      userId: 'test-user',
      createdAt: new Date(),
      updatedAt: new Date()
    }
  ];

  describe('Project Cards Display', () => {
    it('should display project number when present', () => {
      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], mockProjects);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Check if project numbers are displayed
      expect(screen.getByText('#PRJ-001')).toBeInTheDocument();
      expect(screen.getByText('#2024-WEB-001')).toBeInTheDocument();
    });

    it('should not display project number when null', () => {
      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], mockProjects);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Check that Project Gamma (no project number) doesn't show a number
      const gammaCard = screen.getByText('Project Gamma').closest('.hover\\:shadow-md');
      expect(gammaCard).toBeInTheDocument();
      
      // The card should not contain any project number text
      expect(screen.queryByText('#')).not.toBeInTheDocument();
    });

    it('should display project number with correct formatting', () => {
      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], [mockProjects[0]]);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Check if project number is formatted with # prefix
      const projectNumberElement = screen.getByText('#PRJ-001');
      expect(projectNumberElement).toBeInTheDocument();
      expect(projectNumberElement).toHaveClass('text-sm', 'text-gray-500');
    });

    it('should display project name and number together', () => {
      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], [mockProjects[0]]);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Both name and number should be visible in the same card
      const projectCard = screen.getByText('Project Alpha').closest('.hover\\:shadow-md');
      expect(projectCard).toBeInTheDocument();
      expect(screen.getByText('#PRJ-001')).toBeInTheDocument();
    });

    it('should handle various project number formats', () => {
      const diverseProjects = [
        {
          ...mockProjects[0],
          projectNumber: 'PRJ-001'
        },
        {
          ...mockProjects[1],
          id: 'project-2',
          name: 'Project Two',
          projectNumber: '2024-001'
        },
        {
          ...mockProjects[2],
          id: 'project-3',
          name: 'Project Three',
          projectNumber: 'ABC123'
        }
      ];

      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], diverseProjects);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Check different formats are displayed
      expect(screen.getByText('#PRJ-001')).toBeInTheDocument();
      expect(screen.getByText('#2024-001')).toBeInTheDocument();
      expect(screen.getByText('#ABC123')).toBeInTheDocument();
    });
  });

  describe('Project Card Layout', () => {
    it('should maintain proper layout with project number', () => {
      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], [mockProjects[0]]);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Check that the project name has proper styling with truncation
      const projectTitle = screen.getByText('Project Alpha');
      expect(projectTitle).toHaveClass('text-lg', 'truncate');

      // Check that project number has proper spacing
      const projectNumber = screen.getByText('#PRJ-001');
      expect(projectNumber).toHaveClass('text-sm', 'text-gray-500', 'mt-1');
    });

    it('should handle long project names with project numbers', () => {
      const longNameProject = {
        ...mockProjects[0],
        name: 'This is a very long project name that should be truncated properly',
        projectNumber: 'LONG-PROJECT-001'
      };

      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], [longNameProject]);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Both elements should be present even with long names
      expect(screen.getByText('This is a very long project name that should be truncated properly')).toBeInTheDocument();
      expect(screen.getByText('#LONG-PROJECT-001')).toBeInTheDocument();
    });

    it('should maintain card functionality with project numbers', () => {
      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], mockProjects);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Check that edit and delete buttons are still present
      const editButtons = screen.getAllByRole('button', { name: /edit/i });
      const deleteButtons = screen.getAllByRole('button', { name: /delete/i });

      expect(editButtons).toHaveLength(3); // One for each project
      expect(deleteButtons).toHaveLength(3);
    });
  });

  describe('Empty States and Loading', () => {
    it('should handle empty project list correctly', () => {
      const mockQueryClient = createTestQueryClient();
      mockQueryClient.setQueryData(['/api/projects'], []);

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Should show empty state
      expect(screen.getByText('No projects')).toBeInTheDocument();
      expect(screen.getByText('Get started by creating a new project.')).toBeInTheDocument();
    });

    it('should show loading state correctly', () => {
      const mockQueryClient = createTestQueryClient();
      // Don't set any data to simulate loading

      render(
        <QueryClientProvider client={mockQueryClient}>
          <Projects />
        </QueryClientProvider>
      );

      // Should show loading skeletons
      const skeletons = screen.getAllByRole('generic');
      expect(skeletons.some(el => el.classList.contains('animate-pulse'))).toBe(true);
    });
  });
});