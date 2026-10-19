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
module.exports={shouldUseScopedExecution};
