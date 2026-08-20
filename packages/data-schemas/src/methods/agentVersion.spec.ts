import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import { MongoMemoryServer } from 'mongodb-memory-server';
import type { IConversation } from '../types';
import { ConversationMethods, createConversationMethods } from './conversation';
import { createModels } from '../models';

jest.mock('~/config/winston', () => ({
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn(),
}));

let mongoServer: InstanceType<typeof MongoMemoryServer>;
let Conversation: mongoose.Model<IConversation>;
let modelsToCleanup: string[] = [];

const getMessages = jest.fn().mockResolvedValue([]);
const deleteMessages = jest.fn().mockResolvedValue({ deletedCount: 0 });

let methods: ConversationMethods;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();

  const models = createModels(mongoose);
  modelsToCleanup = Object.keys(models);
  Object.assign(mongoose.models, models);
  Conversation = mongoose.models.Conversation as mongoose.Model<IConversation>;

  methods = createConversationMethods(mongoose, { getMessages, deleteMessages });

  await mongoose.connect(mongoUri);
}, 30000);

afterAll(async () => {
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    await collections[key].deleteMany({});
  }
  for (const modelName of modelsToCleanup) {
    if (mongoose.models[modelName]) {
      delete mongoose.models[modelName];
    }
  }
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await Conversation.deleteMany({});
});

const saveConvo = (...args: Parameters<ConversationMethods['saveConvo']>) =>
  methods.saveConvo(...args) as Promise<IConversation | null>;

describe('agentVersion write-once immutability (8S5)', () => {
  test('first save sets agentVersion on a new conversation', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const conversationId = uuidv4();

    const convo = await saveConvo(
      { userId },
      { conversationId, title: 'Test', agentVersion: 3 },
    );

    expect(convo).toBeDefined();
    expect(convo!.agentVersion).toBe(3);
  });

  test('a later update with a DIFFERENT agentVersion on a doc that already has one is stripped/ignored (existing value preserved)', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const conversationId = uuidv4();

    await saveConvo({ userId }, { conversationId, title: 'Test', agentVersion: 1 });

    const updated = await saveConvo(
      { userId },
      { conversationId, title: 'Test updated', agentVersion: 99 },
    );

    expect(updated!.agentVersion).toBe(1);
  });

  test('an update on a doc whose agentVersion is still null is allowed to set it', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const conversationId = uuidv4();

    // Created without agentVersion (e.g. base/ephemeral agent conversation).
    await saveConvo({ userId }, { conversationId, title: 'Test' });
    const before = await Conversation.findOne({ conversationId, user: userId }).lean();
    expect(before?.agentVersion == null).toBe(true);

    const updated = await saveConvo(
      { userId },
      { conversationId, title: 'Test', agentVersion: 5 },
    );

    expect(updated!.agentVersion).toBe(5);
  });

  test('an update that never mentions agentVersion does not disturb an existing pinned value', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const conversationId = uuidv4();

    await saveConvo({ userId }, { conversationId, title: 'Test', agentVersion: 7 });
    const updated = await saveConvo({ userId }, { conversationId, title: 'Renamed' });

    expect(updated!.agentVersion).toBe(7);
    expect(updated!.title).toBe('Renamed');
  });

  test('agentVersion pinning is per-conversation — a second, unrelated conversation is unaffected', async () => {
    const userId = new mongoose.Types.ObjectId().toString();
    const convoA = uuidv4();
    const convoB = uuidv4();

    await saveConvo({ userId }, { conversationId: convoA, title: 'A', agentVersion: 1 });
    await saveConvo({ userId }, { conversationId: convoB, title: 'B', agentVersion: 2 });

    const a = await Conversation.findOne({ conversationId: convoA, user: userId }).lean();
    const b = await Conversation.findOne({ conversationId: convoB, user: userId }).lean();
    expect(a?.agentVersion).toBe(1);
    expect(b?.agentVersion).toBe(2);
  });
});
