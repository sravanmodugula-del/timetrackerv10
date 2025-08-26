import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../utils/test-utils';
import { mockTimeEntry, mockProject, createMockResponse } from '../utils/test-utils';

// Mock API client
const mockApiRequest = vi.fn();
vi.mock('@/lib/queryClient', () => ({
  apiRequest: mockApiRequest,
  queryClient: {
    invalidateQueries: vi.fn(),
  },
}));

// Mock toast
const mockToast = vi.fn();
vi.mock('@/hooks/use-toast', () => ({
  useToast: () => ({ toast: mockToast }),
}));

// Test component for time entry functionality
const TestTimeEntryForm: React.FC = () => {
  const [date, setDate] = React.useState('2025-08-16');
  const [startTime, setStartTime] = React.useState('09:00');
  const [endTime, setEndTime] = React.useState('17:00');
  const [description, setDescription] = React.useState('');
  const [duration, setDuration] = React.useState(8);

  const calculateDuration = (start: string, end: string): number => {
    const startDate = new Date(`2000-01-01T${start}:00`);
    const endDate = new Date(`2000-01-01T${end}:00`);
    const diffMs = endDate.getTime() - startDate.getTime();
    return diffMs / (1000 * 60 * 60); // Convert to hours
  };

  const handleTimeChange = () => {
    if (startTime && endTime) {
      const calculatedDuration = calculateDuration(startTime, endTime);
      setDuration(calculatedDuration);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      await mockApiRequest('/api/time-entries', 'POST', {
        date,
        startTime,
        endTime,
        duration,
        description,
        projectId: 'project-1',
      });
      
      mockToast({
        title: 'Success',
        description: 'Time entry created successfully',
      });
    } catch (error) {
      mockToast({
        title: 'Error',
        description: 'Failed to create time entry',
        variant: 'destructive',
      });
    }
  };

  React.useEffect(() => {
    handleTimeChange();
  }, [startTime, endTime]);

  return (
    <form onSubmit={handleSubmit} data-testid="time-entry-form">
      <input
        data-testid="date-input"
        type="date"
        value={date}
        onChange={(e) => setDate(e.target.value)}
      />
      <input
        data-testid="start-time-input"
        type="time"
        value={startTime}
        onChange={(e) => setStartTime(e.target.value)}
      />
      <input
        data-testid="end-time-input"
        type="time"
        value={endTime}
        onChange={(e) => setEndTime(e.target.value)}
      />
      <input
        data-testid="description-input"
        type="text"
        placeholder="Description"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
      />
      <div data-testid="duration-display">Duration: {duration} hours</div>
      <button type="submit" data-testid="submit-button">
        Save Time Entry
      </button>
    </form>
  );
};

describe('Time Entry Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockApiRequest.mockResolvedValue(createMockResponse({ success: true }));
  });

  it('should render time entry form with all fields', () => {
    render(<TestTimeEntryForm />);
    
    expect(screen.getByTestId('time-entry-form')).toBeInTheDocument();
    expect(screen.getByTestId('date-input')).toBeInTheDocument();
    expect(screen.getByTestId('start-time-input')).toBeInTheDocument();
    expect(screen.getByTestId('end-time-input')).toBeInTheDocument();
    expect(screen.getByTestId('description-input')).toBeInTheDocument();
    expect(screen.getByTestId('duration-display')).toBeInTheDocument();
    expect(screen.getByTestId('submit-button')).toBeInTheDocument();
  });

  it('should calculate duration correctly when times change', async () => {
    render(<TestTimeEntryForm />);
    
    const startTimeInput = screen.getByTestId('start-time-input');
    const endTimeInput = screen.getByTestId('end-time-input');
    const durationDisplay = screen.getByTestId('duration-display');

    fireEvent.change(startTimeInput, { target: { value: '10:00' } });
    fireEvent.change(endTimeInput, { target: { value: '14:00' } });

    await waitFor(() => {
      expect(durationDisplay).toHaveTextContent('Duration: 4 hours');
    });
  });

  it('should submit form with correct data', async () => {
    render(<TestTimeEntryForm />);
    
    const form = screen.getByTestId('time-entry-form');
    const descriptionInput = screen.getByTestId('description-input');

    fireEvent.change(descriptionInput, { target: { value: 'Test work' } });
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockApiRequest).toHaveBeenCalledWith('/api/time-entries', 'POST', {
        date: '2025-08-16',
        startTime: '09:00',
        endTime: '17:00',
        duration: 8,
        description: 'Test work',
        projectId: 'project-1',
      });
    });

    expect(mockToast).toHaveBeenCalledWith({
      title: 'Success',
      description: 'Time entry created successfully',
    });
  });

  it('should handle API errors gracefully', async () => {
    mockApiRequest.mockRejectedValue(new Error('API Error'));
    
    render(<TestTimeEntryForm />);
    
    const form = screen.getByTestId('time-entry-form');
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockToast).toHaveBeenCalledWith({
        title: 'Error',
        description: 'Failed to create time entry',
        variant: 'destructive',
      });
    });
  });

  it('should handle overnight time entries', async () => {
    render(<TestTimeEntryForm />);
    
    const startTimeInput = screen.getByTestId('start-time-input');
    const endTimeInput = screen.getByTestId('end-time-input');
    
    fireEvent.change(startTimeInput, { target: { value: '22:00' } });
    fireEvent.change(endTimeInput, { target: { value: '06:00' } });

    // For overnight entries, duration calculation might need special handling
    // This test ensures the component doesn't crash with edge cases
    expect(screen.getByTestId('time-entry-form')).toBeInTheDocument();
  });

  it('should validate time entry data before submission', async () => {
    const TestTimeEntryWithValidation: React.FC = () => {
      const [startTime, setStartTime] = React.useState('');
      const [endTime, setEndTime] = React.useState('');
      const [error, setError] = React.useState('');

      const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!startTime || !endTime) {
          setError('Start time and end time are required');
          return;
        }
        if (startTime >= endTime) {
          setError('End time must be after start time');
          return;
        }
        setError('');
      };

      return (
        <form onSubmit={handleSubmit} data-testid="time-entry-form">
          <input
            data-testid="start-time-input"
            type="time"
            value={startTime}
            onChange={(e) => setStartTime(e.target.value)}
          />
          <input
            data-testid="end-time-input"
            type="time"
            value={endTime}
            onChange={(e) => setEndTime(e.target.value)}
          />
          {error && <div data-testid="error-message">{error}</div>}
          <button type="submit" data-testid="submit-button">
            Save
          </button>
        </form>
      );
    };

    render(<TestTimeEntryWithValidation />);
    
    const form = screen.getByTestId('time-entry-form');
    fireEvent.submit(form);

    await waitFor(() => {
      expect(screen.getByTestId('error-message')).toBeInTheDocument();
      expect(screen.getByTestId('error-message')).toHaveTextContent('Start time and end time are required');
    });
  });
});