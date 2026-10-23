import type { SettingDefinition } from 'librechat-data-provider';

/** A model declares which values and transport it supports; no vendor heuristics. */
export type ModelReasoningProfile = {
  transport: string;
  options: string[];
  default: string;
};

export type ModelReasoningProfiles = Record<string, ModelReasoningProfile>;

/** Both the chat and saved-agent parameter panels use the same policy UI. */
export function resolveModelReasoningControls(
  definitions: SettingDefinition[],
  profiles: ModelReasoningProfiles | undefined,
  model: string,
  isAdmin: boolean,
): SettingDefinition[] {
  // Staff never get an effort override, including third-party generic sliders.
  const withoutEffort = definitions.filter((item) => item.key !== 'reasoning_effort');
  if (!isAdmin) {
    return withoutEffort;
  }
  // Unmanaged endpoints continue with their existing native controls.
  if (profiles === undefined) {
    return definitions;
  }
  const policy = profiles[model];
  if (
    policy?.transport !== 'chat.completions.reasoning_effort' ||
    !Array.isArray(policy.options) ||
    !policy.options.length ||
    !policy.options.includes(policy.default)
  ) {
    return withoutEffort;
  }
  return [
    ...withoutEffort,
    {
      key: 'reasoning_effort',
      type: 'enum',
      component: 'dropdown',
      optionType: 'model',
      label: 'com_endpoint_reasoning_effort',
      labelCode: true,
      columnSpan: 2,
      options: policy.options,
      default: policy.default,
    } as SettingDefinition,
  ];
}
