'use strict';

// Historical production registrations use "cbhr-pc" or dashed aliases. New registrations
// use an owner-scoped UUID name. Both require the user's live session and its
// separately verified MCP configuration before attachment.
const PC_SERVER_NAME =
  /^(?:cbhr-pc(?:-[a-z0-9]+)*|cbhr_pc_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;
const PC_TOOL_PREFIX = /^cbhr_pc_/i;
const LEGACY_PC_TOOL_NAME = /^cbhr-pc(?:-[a-z0-9]+)*$/i;

function isPCToolKey(name, delimiter) {
  if (typeof name !== 'string' || !name.includes(delimiter)) return false;
  const suffix = name.slice(name.lastIndexOf(delimiter) + delimiter.length);
  return PC_TOOL_PREFIX.test(suffix) || LEGACY_PC_TOOL_NAME.test(suffix);
}

function isTrustedPCConfig(config) {
  if (config?.title !== 'CBHR PC' || config.type !== 'streamable-http') return false;
  try {
    const url = new URL(config.url);
    return (
      url.protocol === 'https:' &&
      !url.port &&
      url.hostname.endsWith('.kelownarealestate.com') &&
      url.pathname.replace(/\/+$/, '') === '/mcp' &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash
    );
  } catch {
    return false;
  }
}

/** Resolve the physical PC per signed-in model turn, never from client MCP state. */
async function resolveEffectivePCTools({
  userId,
  tools = [],
  canUseServers,
  collection,
  getServerConfig,
  delimiter,
  allToolName,
  now = () => new Date(),
}) {
  const selected = Array.isArray(tools) ? tools : [];
  const withoutPC = selected.filter((name) => !isPCToolKey(name, delimiter));
  if (
    !collection ||
    typeof getServerConfig !== 'function' ||
    typeof userId !== 'string' ||
    !/^[a-f0-9]{24}$/i.test(userId)
  ) {
    return withoutPC;
  }
  const live = await collection.findOne({
    userId,
    state: 'active',
    expiresAt: { $gt: now() },
  });
  if (!live || !PC_SERVER_NAME.test(live.serverName || '')) return withoutPC;
  const allowed = typeof canUseServers === 'function' ? await canUseServers() : canUseServers;
  if (!allowed) return withoutPC;
  const config = await getServerConfig(live.serverName, userId);
  if (!isTrustedPCConfig(config)) return withoutPC;
  const wildcard = `${allToolName}${delimiter}${live.serverName}`;
  return withoutPC.includes(wildcard) ? withoutPC : [...withoutPC, wildcard];
}

module.exports = { resolveEffectivePCTools, isPCToolKey, isTrustedPCConfig };
