import { renderHook } from '@testing-library/react';
import type { TStartupConfig, TEndpointsConfig } from 'librechat-data-provider';
import { useEndpoints } from './useEndpoints';

jest.mock('librechat-data-provider/react-query', () => ({
  useGetModelsQuery: () => ({ data: { 'CBHR AI': ['stage-alpha', 'stage-beta'] } }),
}));
jest.mock('~/data-provider', () => ({
  useGetEndpointsQuery: () => ({ data: ['CBHR AI'] }),
}));
jest.mock('~/hooks', () => ({
  useHasAccess: () => false,
  useShowMarketplace: () => false,
}));
jest.mock('~/utils', () => ({
  getIconKey: () => 'none',
  mapEndpoints: (x: unknown) => x,
}));
jest.mock('./Icons', () => ({ icons: {} }));

const endpointConfig = {
  'CBHR AI': { type: 'custom', userProvide: false },
} as unknown as TEndpointsConfig;
function hookFor(modelSelect?: boolean) {
  const config = {
    interface: modelSelect === undefined ? {} : { modelSelect },
    modelSpecs: { addedEndpoints: ['CBHR AI'], list: [] },
  } as unknown as TStartupConfig;
  return renderHook(() =>
    useEndpoints({
      agents: [],
      assistantsMap: {},
      endpointsConfig: endpointConfig,
      startupConfig: config,
    }),
  ).result.current.mappedEndpoints;
}

describe('ADMIN chat endpoint model visibility', () => {
  it('renders both managed model IDs when optional modelSelect is omitted', () => {
    const endpoints = hookFor(undefined);
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0].value).toBe('CBHR AI');
    expect(endpoints[0].models?.map((model) => model.name)).toEqual(['stage-alpha', 'stage-beta']);
  });
  it('respects explicitly disabled modelSelect and hides endpoint rows', () => {
    expect(hookFor(false)).toEqual([]);
  });
});
