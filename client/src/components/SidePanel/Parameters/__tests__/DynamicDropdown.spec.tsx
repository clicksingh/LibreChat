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

describe('DynamicDropdown native reasoning effort', () => {
  it('uses an accessible native select and commits the non-default choice', () => {
    const { update, setOption } = renderDropdown('reasoning_effort');
    const select = screen.getByRole('combobox', { name: 'Reasoning Effort' });
    expect(select).toHaveValue('max');
    expect(screen.getAllByRole('option').map((option) => option.textContent)).toEqual([
      'low',
      'high',
      'max',
    ]);
    fireEvent.change(select, { target: { value: 'high' } });
    expect(setOption).toHaveBeenCalledWith('reasoning_effort');
    expect(update).toHaveBeenCalledWith('high');
  });

  it('respects readonly mode on the native reasoning selector', () => {
    renderDropdown('reasoning_effort', true);
    expect(screen.getByRole('combobox', { name: 'Reasoning Effort' })).toBeDisabled();
  });

  it('preserves the existing custom dropdown for other settings', () => {
    renderDropdown('other_setting');
    expect(screen.queryByRole('combobox', { name: 'Reasoning Effort' })).not.toBeInTheDocument();
  });
});
