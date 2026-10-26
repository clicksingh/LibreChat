import { act, render, screen } from '@testing-library/react';
import PlaceholderRow from '../PlaceholderRow';

jest.mock('~/hooks', () => ({
  useLocalize: () => (key: string) => (key === 'com_ui_working' ? 'Working...' : key),
}));

describe('PlaceholderRow', () => {
  it('shows an accessible working indicator while generation is active', () => {
    render(<PlaceholderRow />);
    expect(screen.getByRole('status')).toHaveTextContent('Working...');
    expect(screen.getByTestId('generation-working-indicator')).toHaveClass('h-[31px]');
    expect(screen.queryByText('1m')).not.toBeInTheDocument();
  });

  it('reports elapsed minutes during a long request and cleans up its timer', () => {
    jest.useFakeTimers();
    try {
      const { unmount } = render(<PlaceholderRow />);
      act(() => jest.advanceTimersByTime(59_000));
      expect(screen.queryByText('1m')).not.toBeInTheDocument();
      act(() => jest.advanceTimersByTime(1_000));
      expect(screen.getByRole('status')).toHaveTextContent('1m');
      act(() => jest.advanceTimersByTime(120_000));
      expect(screen.getByRole('status')).toHaveTextContent('3m');
      unmount();
      expect(jest.getTimerCount()).toBe(0);
    } finally {
      jest.useRealTimers();
    }
  });
});
