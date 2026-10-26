import { render, screen } from '@testing-library/react';
import PlaceholderRow from '../PlaceholderRow';

jest.mock('~/hooks', () => ({
  useLocalize: () => (key: string) => (key === 'com_ui_working' ? 'Working…' : key),
}));

describe('PlaceholderRow', () => {
  it('shows an accessible working indicator while generation is active', () => {
    render(<PlaceholderRow />);

    expect(screen.getByRole('status')).toHaveTextContent('Working…');
    expect(screen.getByTestId('generation-working-indicator')).toHaveClass('h-[31px]');
  });
});
