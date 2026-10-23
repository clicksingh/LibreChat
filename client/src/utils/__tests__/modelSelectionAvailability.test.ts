import { isModelSelectionEnabled } from '../modelSelectionAvailability';

describe('model-select startup config', () => {
  it('permits model browsing if backend omits the optional field', () => {
    expect(isModelSelectionEnabled(undefined)).toBe(true);
    expect(isModelSelectionEnabled(true)).toBe(true);
  });
  it('respects an explicit disabled policy', () => {
    expect(isModelSelectionEnabled(false)).toBe(false);
  });
});
