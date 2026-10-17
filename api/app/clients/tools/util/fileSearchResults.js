'use strict';

/**
 * Preserve the original file identity through partially failed RAG requests.
 * Filtering out a failed response before joining by array index can silently
 * attribute content and citations to a different accessible document.
 * This pure function is deliberately independent of HTTP and model runtime.
 */
function flattenFileSearchResults(results, files) {
  const mapped = [];
  for (let i = 0; i < results.length; i++) {
    const response = results[i];
    const file = files[i];
    if (!file || !Array.isArray(response?.data)) continue;
    for (const hit of response.data) {
      if (!Array.isArray(hit) || !hit[0]) continue;
      const [docInfo, distance] = hit;
      if (typeof distance !== 'number' || !Number.isFinite(distance)) continue;
      if (typeof docInfo.page_content !== 'string') continue;
      const source = docInfo.metadata?.source;
      const sourceName = typeof source === 'string'
        ? source.replaceAll('\\', '/').split('/').pop()
        : null;
      mapped.push({
        filename: sourceName || file.filename || 'Indexed file',
        content: docInfo.page_content,
        distance,
        file_id: file.file_id,
        page: docInfo.metadata?.page || null,
      });
    }
  }
  return mapped.sort((a, b) => a.distance - b.distance).slice(0, 10);
}

module.exports = { flattenFileSearchResults };
