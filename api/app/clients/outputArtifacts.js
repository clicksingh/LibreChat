/**
 * Normalize the final saved assistant attachment list. Tools may revise the
 * same logical artifact many times during one generation. Only its newest
 * metadata event belongs in the durable response; ephemeral no-ID events
 * retain their original order.
 */
function latestAttachments(items) {
  const output = [];
  const byFileId = new Map();
  for (const file of items || []) {
    if (!file) continue;
    const id = typeof file.file_id === 'string' && file.file_id ? file.file_id : null;
    if (!id) {
      output.push(file);
      continue;
    }
    if (!byFileId.has(id)) {
      byFileId.set(id, output.length);
      output.push(file);
    } else {
      const index = byFileId.get(id);
      output[index] = {...output[index], ...file};
    }
  }
  return output;
}
function missingFinalArtifactResponse(message) {
  // Tool-only content is not a final user-facing answer. The UI prefers
  // structured content over message.text, so append a visible text part too.
  if (typeof message.text !== 'string' || message.text.trim()) return false;
  if (Array.isArray(message.content) && message.content.some((part) =>
    (typeof part === 'string' && part.trim()) ||
    (part?.type === 'text' && typeof part.text === 'string' && part.text.trim())
  )) return false;
  const files = (message.attachments || []).filter(x => x.file_id && x.filename);
  if (!files.length) return false;
  const docs = files.filter(x => /\.(docx?|pdf|xlsx?|pptx?)$/i.test(x.filename));
  if (!docs.length) return false;
  message.text = 'I prepared document files for review. Please check the attached deliverables and verify their content before using them as finalized procedures.';
  if (Array.isArray(message.content)) {
    message.content.push({ type: 'text', text: message.text });
  }
  return true;
}
module.exports = { latestAttachments, missingFinalArtifactResponse };
