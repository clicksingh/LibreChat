'use strict';

const { PermissionBits, PrincipalType, ResourceType } = require('librechat-data-provider');
const { reconcileOwnedWorkspacesForDeletedUser } = require('./userDeletion');

const chain = (value) => ({
  select() {
    return this;
  },
  lean: async () => value,
});

test('transfers metadata ownership to another user owner', async () => {
  const Workspace = {
    find: jest.fn(() => chain([{ _id: 'w1' }])),
    updateOne: jest.fn().mockResolvedValue({}),
  };
  const AclEntry = {
    find: jest.fn(() =>
      chain([
        { principalId: 'leaving', permBits: PermissionBits.DELETE },
        { principalId: 'remaining', permBits: PermissionBits.DELETE },
      ]),
    ),
  };
  await expect(
    reconcileOwnedWorkspacesForDeletedUser({
      Workspace,
      AclEntry,
      userId: 'leaving',
    }),
  ).resolves.toEqual({ transferred: 1, archived: 0 });
  expect(AclEntry.find).toHaveBeenCalledWith(
    expect.objectContaining({
      resourceType: ResourceType.WORKSPACE,
      principalType: PrincipalType.USER,
    }),
  );
  expect(Workspace.updateOne).toHaveBeenCalledWith(
    { _id: 'w1' },
    { $set: { ownerId: 'remaining' } },
  );
});

test('archives when no other user owner exists', async () => {
  const Workspace = {
    find: jest.fn(() => chain([{ _id: 'w1' }])),
    updateOne: jest.fn().mockResolvedValue({}),
  };
  const AclEntry = {
    find: jest.fn(() => chain([{ principalId: 'viewer', permBits: PermissionBits.VIEW }])),
  };
  await expect(
    reconcileOwnedWorkspacesForDeletedUser({
      Workspace,
      AclEntry,
      userId: 'leaving',
    }),
  ).resolves.toEqual({ transferred: 0, archived: 1 });
  expect(Workspace.updateOne).toHaveBeenCalledWith({ _id: 'w1' }, { $set: { state: 'archived' } });
});
