/** The model-selector default is enabled; only an explicit false hides it. */
export function isModelSelectionEnabled(modelSelect?: boolean): boolean {
  return modelSelect !== false;
}
