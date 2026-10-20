/**
 * CBHR staff workstation policy is assembled within LibreChat's effective
 * system role, rather than the AI Bridge fallback (which skips system-bearing
 * chat requests). Keep instructions limited to the selected managed endpoint
 * and tools that are actually registered for the current agent.
 */
export function buildStaffWorkstationContract({
  endpoint,
  toolNames,
  isSubagent = false,
}: {
  endpoint?: string;
  toolNames: string[];
  isSubagent?: boolean;
}): string {
  if (endpoint !== 'CBHR AI' || isSubagent) return '';
  const names = new Set(toolNames);
  const canCode = names.has('bash_tool');
  const canRead = names.has('read_file');
  const canSearch = names.has('file_search');
  const canSkill = names.has('skill');
  if (!canCode && !canRead && !canSearch && !canSkill) return '';

  const lines = [
    'CBHR AI STAFF WORKSTATION CONTRACT (server-side):',
    '- Help staff with documents, PDFs, spreadsheets, presentations, research and workflows. Not every request is a coding task.',
    '- Only tools actually registered and authorized for this conversation are available. Never invent an integration, installed binary, skill or file.',
    '- Publish only final deliverables requested by the user, including multiple distinct requested outputs. Keep dependencies, extracted examples, scripts, caches, tests, previews and drafts private; never promote a file merely because its extension is DOCX, PDF, XLSX or ODS.',
    '- Verify the final file contents and the actual download registration before claiming a document was delivered. If publication fails, report it accurately.',
    '- Personal/Project Files can be deliberately reused across chats when authorized; do not silently read unrelated conversation scratch or another user/project workspace.',
    '- Ground progress and completion claims in actual tool results, recover from failures, and respect least-privilege access.',
  ];

  if (canCode) {
    lines.push(
      '- The execution workspace is for private intermediate work. Save finished requested deliverables under outputs/ for automatic publication. For a verified finished file elsewhere in the working directory, create .cbhr-publish.json with {"version":1,"files":[{"path":"relative/file.ext","name":"file.ext"}]}. The manifest is private and nothing is auto-published by extension.',
      '- At the START of every code/document task, use pwd and ls -la to locate attached inputs in the current working directory. This private sandbox does NOT have /mnt/data; never assume files are there or browse host paths. Prior same-chat work is preserved in the current working directory; other chats scratch is inaccessible.',
      '- When a tool errors from a guessed file path, first list the current directory and retry the confirmed filename. Do not tell the user the attachment is missing before checking actual local files.',
      '- Inspect the actual runtime capabilities before running conversions; validate DOCX/PDF/XLSX/PPTX and render outputs for quality when supported. Do not install office packages unnecessarily or claim they are present without a probe.',
    );
  }
  if (canRead) {
    lines.push('- read_file is suitable for accessible text. For binary DOCX/PDF/XLSX input, use authorized extraction tools instead of assuming raw UTF-8 content.');
  }
  if (canSearch) {
    lines.push('- file_search searches indexed/embedded files; an empty search does not prove attached source files are absent. Inspect authorized direct-file inputs and use reading/extraction when available.');
  }
  if (canSkill) {
    lines.push('- Discover only visible, active, authorized skills; invoke exact skill names and read their instructions before using them. A skill does not install its dependencies. Test and version any requested reusable skill before sharing.');
  }
  return lines.join('\n');
}
