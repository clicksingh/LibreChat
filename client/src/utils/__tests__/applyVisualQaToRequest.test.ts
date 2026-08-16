import type { TEphemeralAgent } from 'librechat-data-provider';
import { applyVisualQaToRequest } from '../endpoints';

/**
 * Tests for applyVisualQaToRequest — the 8S3C.1 task B request-time coupling of
 * `document_visual_qa` to `execute_code`.
 *
 * Desired behaviors:
 * - When Run Code is enabled (`execute_code: true`), the outgoing chat request
 *   also requests `document_visual_qa` automatically (no second toggle exists).
 * - When code execution is off, the agent is returned unchanged (identity) —
 *   a negative user's request never carries the visual-QA flag.
 * - The function is pure: it never mutates its input.
 *
 * NOTE: this is intent coupling only. The server keeps the final exposure gate
 * (codeEnvAvailable AND the explicit agent request); a bare client flag is never
 * trusted as authorization.
 */

describe('applyVisualQaToRequest', () => {
  it('adds document_visual_qa when execute_code is enabled', () => {
    const agent: TEphemeralAgent = {
      execute_code: true,
      web_search: false,
      mcp: ['github'],
    };

    const result = applyVisualQaToRequest(agent);

    expect(result).toEqual({
      execute_code: true,
      web_search: false,
      mcp: ['github'],
      document_visual_qa: true,
    });
  });

  it('keeps an existing document_visual_qa: true when execute_code is enabled', () => {
    const agent: TEphemeralAgent = {
      execute_code: true,
      document_visual_qa: true,
    };

    expect(applyVisualQaToRequest(agent)).toEqual({
      execute_code: true,
      document_visual_qa: true,
    });
  });

  it('does not force document_visual_qa when execute_code is explicitly false', () => {
    const agent: TEphemeralAgent = { execute_code: false, document_visual_qa: false };

    expect(applyVisualQaToRequest(agent)).toEqual({ execute_code: false, document_visual_qa: false });
  });

  it('returns the same value (identity) when execute_code is absent', () => {
    const agent: TEphemeralAgent = { web_search: true };

    expect(applyVisualQaToRequest(agent)).toBe(agent);
  });

  it('returns null unchanged', () => {
    expect(applyVisualQaToRequest(null)).toBeNull();
  });

  it('returns undefined unchanged', () => {
    expect(applyVisualQaToRequest(undefined)).toBeUndefined();
  });

  it('does not mutate the input agent', () => {
    const agent: TEphemeralAgent = { execute_code: true, web_search: true };
    const snapshot = { ...agent };

    applyVisualQaToRequest(agent);

    expect(agent).toEqual(snapshot);
    expect('document_visual_qa' in agent).toBe(false);
  });

  it('returns a new object when coupling (does not alias the input)', () => {
    const agent: TEphemeralAgent = { execute_code: true };

    expect(applyVisualQaToRequest(agent)).not.toBe(agent);
  });
});
