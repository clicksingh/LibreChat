'use strict';

const { PermissionBits, PrincipalType, ResourceType } = require('librechat-data-provider');

async function reconcileOwnedWorkspacesForDeletedUser({ Workspace, AclEntry, userId }) {
  if (!Workspace || !AclEntry || !userId) return { transferred: 0, archived: 0 };

  const owned = await Workspace.find({ ownerId: String(userId) })
    .select('_id')
    .lean();
  let transferred = 0;
  let archived = 0;

  for (const workspace of owned) {
    const entries = await AclEntry.find({
      resourceType: ResourceType.WORKSPACE,
      resourceId: workspace._id,
      principalType: PrincipalType.USER,
    })
      .select('principalId permBits')
      .lean();

    const replacement = entries
      .filter(
        (entry) =>
          String(entry.principalId) !== String(userId) &&
          (entry.permBits & PermissionBits.DELETE) === PermissionBits.DELETE,
      )
      .sort((a, b) => String(a.principalId).localeCompare(String(b.principalId)))[0];

    if (replacement) {
      await Workspace.updateOne(
        { _id: workspace._id },
        { $set: { ownerId: String(replacement.principalId) } },
      );
      transferred += 1;
      continue;
    }

    await Workspace.updateOne({ _id: workspace._id }, { $set: { state: 'archived' } });
    archived += 1;
  }

  return { transferred, archived };
}

module.exports = { reconcileOwnedWorkspacesForDeletedUser };
