import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../utils/test-utils';

// Mock navigation component
const TestNavigationComponent: React.FC = () => {
  const [activeTab, setActiveTab] = React.useState('dashboard');
  
  const navigationItems = [
    { id: 'dashboard', label: 'Dashboard', href: '/dashboard' },
    { id: 'projects', label: 'Projects', href: '/projects' },
    { id: 'time-log', label: 'Time Log', href: '/time-log' },
    { id: 'reports', label: 'Reports', href: '/reports' }
  ];

  return (
    <nav data-testid="main-navigation">
      {navigationItems.map(item => (
        <button
          key={item.id}
          data-testid={`nav-${item.id}`}
          className={activeTab === item.id ? 'active' : ''}
          onClick={() => setActiveTab(item.id)}
        >
          {item.label}
        </button>
      ))}
      <div data-testid="active-tab">{activeTab}</div>
    </nav>
  );
};

describe('Navigation Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should render navigation items', () => {
    render(<TestNavigationComponent />);
    
    expect(screen.getByTestId('main-navigation')).toBeInTheDocument();
    expect(screen.getByTestId('nav-dashboard')).toBeInTheDocument();
    expect(screen.getByTestId('nav-projects')).toBeInTheDocument();
    expect(screen.getByTestId('nav-time-log')).toBeInTheDocument();
    expect(screen.getByTestId('nav-reports')).toBeInTheDocument();
  });

  it('should have dashboard as default active tab', () => {
    render(<TestNavigationComponent />);
    
    expect(screen.getByTestId('active-tab')).toHaveTextContent('dashboard');
    expect(screen.getByTestId('nav-dashboard')).toHaveClass('active');
  });

  it('should switch active tab when clicked', () => {
    render(<TestNavigationComponent />);
    
    const projectsButton = screen.getByTestId('nav-projects');
    fireEvent.click(projectsButton);
    
    expect(screen.getByTestId('active-tab')).toHaveTextContent('projects');
    expect(projectsButton).toHaveClass('active');
  });

  it('should update active state correctly', () => {
    render(<TestNavigationComponent />);
    
    // Click on time-log
    fireEvent.click(screen.getByTestId('nav-time-log'));
    expect(screen.getByTestId('nav-time-log')).toHaveClass('active');
    expect(screen.getByTestId('nav-dashboard')).not.toHaveClass('active');
    
    // Click on reports
    fireEvent.click(screen.getByTestId('nav-reports'));
    expect(screen.getByTestId('nav-reports')).toHaveClass('active');
    expect(screen.getByTestId('nav-time-log')).not.toHaveClass('active');
  });
});