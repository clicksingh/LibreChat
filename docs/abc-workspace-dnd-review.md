# ABC Files drag/reuse reviewer handoff (LibreChat)

**Base:** 96534c3b12a8a9e2305fc6ec3538637a2804d240, separate isolated worktree.
**Scope:** client-only UI; no CodeAPI or LibreChat server authorization changes, no production deployment.

## Existing contract preserved

The ABC integration already supplies HTML5 draggable Personal/Project Files rows,
a custom application/x-cbhr-workspace-file drag payload, ChatForm drop handling,
and an accessible Paperclip fallback. The composer sends opaque sessionId/fileId
to the existing authenticated attach endpoint; it does NOT fetch/download and
re-upload content in the browser. api/server/services/Workspace/attach.js resolves
the requested file against a server-authorized workspace listing, verifies
conversation/project scope, and performs a bounded server-side copy. The browser
drag payload is a hint, not permission.

## Reliability and usability fixes

- The existing attachment callback previously set filesLoading=true and never
  restored false. Success, failure, and pending-chip removal now all finish via
  releaseAttach in finally. Send is no longer left permanently disabled.
- The new synchronous acquisition guard rejects rapid duplicate drops while a
  request is pending, before React delivers filesLoading to the next render;
  its release is idempotent for retry after errors.
- The panel's global Paperclip event is processed only by the primary composer
  when multi-chat comparison mounts several ChatForms. Direct drops still attach
  to the exact targeted composer.
- Workspace drag payload and click event details are validated as opaque keys,
  nonempty filename, positive integer byte count and explicit Personal/Project
  scope before triggering attachment. No client-supplied session/project keys
  are used to bypass backend ACL checks.
- The Files panel visibly explains dragging to the composer and using Paperclip
  as a fallback. Standard OS file drops remain on the existing upload path.

## Tests

- Focused Jest suites: client/src/utils/__tests__/workspaceAttachment.spec.ts
  and client/src/components/SidePanel/Workspace/__tests__/FileTable.spec.tsx.
  They cover personal/project scope, drop vs OS files, malicious metadata,
  event fallback, click, drag source, and duplicate-drop lock/release.
- npm run typecheck --workspace client.
- npm run build:client (production Vite, isolated worktree, prebuilt unchanged
  dependency package artifacts copied from exact ABC baseline).

## Release caveats

UI proof is not a live browser drag acceptance. Verify mouse/touchpad drag of a
published Personal and Project file into a matching current chat, failure toast
for mismatched workspace, duplicate-drop suppression and restored Send button
after both server success and rejected/trash/bad-file paths, plus Paperclip
keyboard fallback. Large files remain limited by server MAX_ATTACH_BYTES.
Do not merge until prime's ABC branch/release gates reconcile the stacked PR.
