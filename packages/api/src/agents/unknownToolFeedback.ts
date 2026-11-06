/**
 * A corrective error for a tool name the runtime did not register.
 * Candidate names MUST come from tools actually loaded for this agent
 * or a server-validated runtime capability, never from a global catalog.
 * This helper never resolves aliases or executes tools.
 */
export function buildUnknownToolError(
  requestedName: string,
  availableNames: Iterable<string>,
): string {
  const requested = requestedName.toLowerCase();
  const firstToken = requested.split(/[_:.-]/, 1)[0];
  const offered = new Set<string>();

  for (const name of availableNames) {
    if (typeof name !== 'string' || !name || name === requestedName) continue;
    const lower = name.toLowerCase();
    const candidateToken = lower.split(/[_:.-]/, 1)[0];
    // A common "mcp"/"tool" prefix is NOT a close match and can leak
    // unrelated server tools; require a meaningful specific name family.
    const sameFamily =
      firstToken.length >= 4 &&
      !['mcp', 'tool'].includes(firstToken) &&
      firstToken === candidateToken;
    const nearExact =
      requested.length >= 4 && (lower.startsWith(requested) || requested.startsWith(lower));
    if (sameFamily || nearExact) offered.add(name);
  }
  const suggestions = [...offered].sort((a, b) => a.localeCompare(b)).slice(0, 3);
  const label = suggestions.length === 1 ? 'Related available tool' : 'Related available tools';
  const correction = suggestions.length
    ? ` ${label}: ${suggestions.map((name) => JSON.stringify(name)).join(', ')}. Use the exact registered name.`
    : ' Use an exact tool name available to this agent.';
  return `Tool ${JSON.stringify(requestedName)} not found.${correction} The requested tool was not executed.`;
}
