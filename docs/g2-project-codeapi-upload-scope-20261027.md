# G2 project CodeAPI file-upload ownership correction (2026-10-27)

## Authority and scope

- Base: LibreChat PR #36 at 511901e3303c338eb257a989ad7532cfd47e3858.
- Isolated patch branch: fix/g2-project-upload-scope-20261027.
- Production remains on cbhr-ai:pr38-da413d042; PR #36 and the V2 promotion remain on HOLD.
- No changes to CodeAPI production service, retention mode, signed-token configuration, or business files.

## Production browser reproduction

Authenticated Aryn ADMIN in a new QA-only project named G2-QA-20261027-01
(workspace 6ae10c34aa7f6c0772735e81) selected project for new chats.
- A test chat completed with G2_OWNER_PASS; Mongo conversation workspaceId matched the QA project.
- A disposable file g2-codeapi-20261027.txt was uploaded through the
  browser's Upload to Code Environment option.
- The file completed upload, but the project Files panel showed No files yet.
- Mongo stored its codeEnvRef as kind=user, id=6a31557594ab025c7537576e,
  instead of the verified project identity.
- The subsequent LLM message returned MODEL_REQUEST_INTERRUPTED; that
  separate response failure must not be counted as a project-file PASS.
- A second disposable text-only attachment g2-disposable-20261027.txt
  followed the normal message-attachment storage path and is not a
  CodeAPI workspace object.

## Root cause

The chat file-upload handler always chose kind=user for message attachments,
even when the conversation was project-scoped. For an unsaved new chat, the
upload form also omitted workspaceId. CodeAPI correctly obeyed the personal
identity in the signed request, so the project Files view was legitimately
empty. This is an ownership-routing defect, not a FileTable rendering bug.

## Change under test

1. For conversation uploads, carry the selected workspaceId in multipart
   data, without treating the client value as authorization.
2. Re-run resolveWorkspaceContext per request before opening upload stream:
   existing conversation scope wins; new project requires live EDIT membership;
   failure denies and must not silently fall back to personal storage.
3. Use project identity and matching signed CodeAPI claim for verified project
   uploads. Preserve user identity for personal chats and agent identity for
   independent agent setup uploads.
4. Keep existing saved personal conversations personal even if an upload body
   supplies a project id. Return 400/401/403/404 from route when applicable.

## Qualification and remaining gates

- Backend file-processing regression suite: 59/59 PASS on patch (first run).
- Workspace authorization suite: 16/16 PASS on patch.
- Production retest: NOT RUN against patch; do not mark G2 PASS yet.
- The named QA project and two disposable files require explicit cleanup
  following acceptance. Never delete unrelated production files.
- Next: exact-head CI, independent review, isolated/staging or bounded
  production acceptance, project owner download/trash/restore/purge,
  non-member/revoked denial, persistence, cleanup, G3 review, G4 rollback.
- Automatic CodeAPI retention apply remains separately unauthorized.
