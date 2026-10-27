import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import type { TSetOption } from 'librechat-data-provider';
import DynamicDropdown from '../DynamicDropdown';
import { ChatContext } from '~/Providers';

type ChatContextValue = React.ContextType<typeof ChatContext>;
const chatContextValue = { preset: null } as unknown as ChatContextValue;

function renderDropdown(settingKey: string, readonly = false) {
  const update = jest.fn();
  const setOption = jest.fn(() => update) as unknown as TSetOption;
  render(
    <ChatContext.Provider value={chatContextValue}>
      <DynamicDropdown
        settingKey={settingKey}
        label="Reasoning Effort"
        defaultValue="max"
        setOption={setOption}
        options={['low', 'high', 'max']}
        conversation={{ reasoning_effort: 'max' }}
        readonly={readonly}
      />
    </ChatContext.Provider>,
  );
  return { update, setOption };
}

describe('DynamicDropdown shared reasoning effort select', () => {
  it('uses the shared accessible select and commits the non-default choice', () => {
    const { update, setOption } = renderDropdown('reasoning_effort');
    const select = screen.getByRole('combobox', { name: 'Reasoning Effort' });
    expect(select).toHaveTextContent('max');
    fireEvent.keyDown(select, { key: 'ArrowDown' });
    const high = screen.getByRole('option', { name: 'high' });
    fireEvent.click(high);
    expect(setOption).toHaveBeenCalledWith('reasoning_effort');
    expect(update).toHaveBeenCalledWith('high');
  });

  it('respects readonly mode on the shared reasoning selector', () => {
    renderDropdown('reasoning_effort', true);
    expect(screen.getByRole('combobox', { name: 'Reasoning Effort' })).toHaveAttribute(
      'data-disabled',
    );
  });

  it('preserves the existing custom dropdown for other settings', () => {
    renderDropdown('other_setting');
    expect(screen.queryByRole('combobox', { name: 'Reasoning Effort' })).not.toBeInTheDocument();
  });
});
