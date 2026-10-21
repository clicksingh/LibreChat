/**
 * 8S3C.1 — J2 malformed visual case (directive item E, journey 2).
 *
 * A request that asks for document_visual_qa WITHOUT the execute_code it must
 * be paired with. The normal UI cannot produce this (applyVisualQaToRequest
 * only couples the flag onto execute_code:true agents), so it is expressed at
 * the request layer through the same /api/agents/chat/:endpoint surface.
 *
 * Expected (probe [B], deployed 89807b0ec): server TOLERATES it — HTTP 200,
 * toolTokenCounts includes document_visual_qa, does NOT include bash_tool. The
 * pairing guarantee lives in the client coupling, not the server. Documented,
 * not auto-healed ("no security/product expectation may be auto-healed").
 */

import { test, expect } from '@playwright/test';
import { chatRequest } from '../utils/api';
import { USERS } from '../utils/constants';

test.describe('J2 — malformed visual case', () => {
  test('document_visual_qa without execute_code: tolerated, bash_tool absent', async () => {
    const r = await chatRequest(USERS.enabled.id, { document_visual_qa: true });
    expect(r.postStatus, `POST should be 200, got ${r.postStatus} (${r.postBody})`).toBe(200);
    expect(
      r.toolTokenCounts,
      `docvqa must register on the client flag alone, got [${r.toolTokenCounts.join(', ')}]`,
    ).toContain('document_visual_qa');
    expect(r.toolTokenCounts, `bash_tool must NOT register without execute_code`).not.toContain(
      'bash_tool',
    );
  });
});
