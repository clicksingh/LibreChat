import React from 'react';
import '@testing-library/jest-dom/extend-expect';
import { render, fireEvent } from 'test/layout-test-utils';
import { useClaimXposeDeviceMutation } from '~/data-provider';
import Devices from '../Devices';

jest.mock('~/data-provider', () => ({
  ...jest.requireActual('~/data-provider'),
  useClaimXposeDeviceMutation: jest.fn(),
}));

const mockClaim = useClaimXposeDeviceMutation as jest.Mock;

describe('Xpose Devices', () => {
  let mutate: jest.Mock;

  beforeEach(() => {
    mutate = jest.fn((_payload, options) => {
      options?.onSuccess?.({ ok: true, state: 'claimed', deviceId: 'device-123' });
    });
    mockClaim.mockReturnValue({
      mutate,
      isLoading: false,
      isSuccess: false,
    });
  });

  it('submits only the trimmed human pairing code', () => {
    const { getByLabelText, getByRole } = render(<Devices />);

    fireEvent.change(getByLabelText('Pairing code'), {
      target: { value: '  ABC-DEF  ' },
    });
    fireEvent.click(getByRole('button', { name: 'Add device' }));

    expect(mutate).toHaveBeenCalledTimes(1);
    expect(mutate.mock.calls[0][0]).toEqual({ code: 'ABC-DEF' });
    expect(Object.keys(mutate.mock.calls[0][0])).toEqual(['code']);
  });

  it('does not submit an empty code', () => {
    const { getByRole } = render(<Devices />);
    expect(getByRole('button', { name: 'Add device' })).toBeDisabled();
    expect(mutate).not.toHaveBeenCalled();
  });
});
