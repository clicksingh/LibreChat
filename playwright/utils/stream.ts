/**
 * 8S3C.1 browser E2E — LibreChat agent-chat SSE stream parser.
 *
 * Mirrors the parsing in /opt/cbhr-ai/verify-doc-workstation-e2e.js (the
 * accepted 8S3C chat E2E): reads `on_context_usage` for toolTokenCounts (the
 * tool names the run used/registered), `on_run_step*` for tool calls, and the
 * `final` event for the response text + conversation id. Used by the host-side
 * forged/malformed assertions ("inspect tool definitions, not just narration").
 */

export interface ParsedStream {
  toolTokenCounts: string[];
  toolCalls: string[];
  finalText: string;
  conversationId: string | null;
  bytes: number;
}

export function parseStream(raw: string): ParsedStream {
  const out: ParsedStream = {
    toolTokenCounts: [],
    toolCalls: [],
    finalText: '',
    conversationId: null,
    bytes: raw.length,
  };
  for (const chunk of raw.split('\n')) {
    if (!chunk.startsWith('data:')) continue;
    let d: any;
    try {
      d = JSON.parse(chunk.slice(5).trim());
    } catch {
      continue;
    }
    const ev = d.event || '';
    if (ev === 'on_context_usage') {
      const cd = d.data?.breakdown || d.data || {};
      const ttc = cd.toolTokenCounts || {};
      for (const name of Object.keys(ttc)) {
        if (!out.toolTokenCounts.includes(name)) out.toolTokenCounts.push(name);
      }
    } else if (ev === 'on_run_step' || ev === 'on_run_step_delta') {
      const tc = d.data?.stepDetails?.tool_calls || d.data?.delta?.tool_calls;
      if (Array.isArray(tc)) {
        for (const t of tc) {
          if (t?.name && !out.toolCalls.includes(t.name)) out.toolCalls.push(t.name);
        }
      }
    } else if (ev === 'final') {
      out.finalText = d.responseMessage?.text || out.finalText;
      out.conversationId =
        d.conversation?.conversationId || d.requestMessage?.conversationId || out.conversationId;
    } else if (ev === 'created') {
      out.conversationId = d.message?.conversationId || out.conversationId;
    }
  }
  return out;
}
