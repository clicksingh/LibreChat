/**
 * B1 opt-in cutover for NEW conversations only. Legacy chats retain their
 * original execution state instead of silently losing prior work.
 *
 * The date is administrator-supplied at rollout; both the date and the
 * existing conversation come from trusted server-side state, not the model.
 */
const UTC_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
function shouldUseScopedExecution({cutoverUtc, conversation}) {
  if (typeof cutoverUtc !== 'string' || !UTC_TIME.test(cutoverUtc) ||
      !Number.isFinite(Date.parse(cutoverUtc))) {
    throw new Error('CBHR_B1_CUTOVER_TIMESTAMP_REQUIRED');
  }
  if (!conversation) return true;
  const value=conversation.createdAt;
  const createdAt=value instanceof Date ? value.getTime() : Date.parse(value);
  // Old records without trustworthy creation time remain legacy, not a
  // guessed "new" session. Releasing them requires explicit migration.
  if (!Number.isFinite(createdAt)) return false;
  return createdAt >= Date.parse(cutoverUtc);
}
// A first-message chat may have a client-assigned UUID before its Convo row
// exists. Treating every non-'new' request ID as an *existing* conversation
// denies valid first messages. Never authorize an ID owned by another user.
const CONVERSATION_UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
async function verifyExecutionConversation({
  userId, conversationId, requestedId, ownedConversation, lookupGlobalConversation,
}) {
  if (!userId || !CONVERSATION_UUID.test(conversationId)) {
    throw new Error('An authenticated conversation is required for code execution');
  }
  if (requestedId && requestedId !== 'new' && requestedId !== conversationId) {
    throw new Error('Conversation execution identity mismatch');
  }
  if (ownedConversation) return ownedConversation;
  // When no owner-scoped Convo exists yet, a UUID may be first-message
  // reservation. Check the global database rather than assuming "foreign".
  // Unknown/legacy identity lookup fails closed.
  if (typeof lookupGlobalConversation !== 'function') {
    throw new Error('Conversation execution access denied');
  }
  const global=await lookupGlobalConversation(conversationId);
  if (global) throw new Error('Conversation execution access denied');
  return null; // unique first-message UUID; new scoped session permitted
}
module.exports={shouldUseScopedExecution,verifyExecutionConversation};
