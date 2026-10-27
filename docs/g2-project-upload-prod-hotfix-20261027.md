# G2 production-hotfix project-upload correction | 2026-10-27

Release lane: LibreChat PR #39 on the production-hotfix branch.
This is not broad V2 PR #36; production rollout is not authorized by this note.

## Reproduction and correction
A project-bound chat uploaded a disposable Code Environment input into
personal storage because the chat upload handler hard-coded the user
identity. The new-chat multipart form also omitted selected workspaceId.
CodeAPI and Workspace Files consequently disagreed on the owner.
This patch passes workspaceId to the server, verifies live project EDIT
membership on each upload, and mints project-scoped CodeAPI access.
Project uploads carry workspaceFileAttachment=true so ordinary chat-file
cleanup cannot erase shared project assets and file grant checks work.

## Last review findings corrected
1. Propagate fail-closed project authorization status (403/404) to the
   /files response, retaining existing userErrorStatusCode precedence.
2. A previously saved PERSONAL conversation retains its stored scope even
   when multipart body supplies a project workspaceId. Add regression case.
The new-chat scope still requires current project membership.

## Release gates
Local focused backend test suites: 75/75 PASS after correction.
Targeted lint and diff check: PASS.
Protected exact-head CI and independent security review must run again.
Keep production image pinned to PR #38 until a reviewed canary is approved.
G2 requires authenticated browser owner file visibility, download,
Trash and restore, cross-user denial, revoked-membership denial, quotas,
and cleanup receipts. Do not alter CodeAPI retention apply mode.
Parallel V2 branch PR #40 remains a distinct release lane with its own CI.
