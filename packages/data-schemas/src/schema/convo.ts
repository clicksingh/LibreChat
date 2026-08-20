import { Schema } from 'mongoose';
import { conversationPreset } from './defaults';
import { IConversation } from '~/types';

const convoSchema: Schema<IConversation> = new Schema(
  {
    conversationId: {
      type: String,
      required: true,
      index: true,
      meiliIndex: true,
    },
    title: {
      type: String,
      default: 'New Chat',
      meiliIndex: true,
    },
    user: {
      type: String,
      index: true,
      meiliIndex: true,
    },
    messages: [{ type: Schema.Types.ObjectId, ref: 'Message' }],
    isTemporary: {
      type: Boolean,
      default: false,
    },
    ...conversationPreset,
    agent_id: {
      type: String,
    },
    tags: {
      type: [String],
      default: [],
      meiliIndex: true,
    },
    chatProjectId: {
      type: String,
      default: null,
      index: true,
    },
    // 8S3D.1: which WORKSPACE (storage/quota boundary) this conversation's
    // code execution/file operations are scoped to. null = personal
    // workspace (the default, unchanged behavior). Set once at conversation
    // creation and treated as immutable thereafter — see
    // resolveWorkspaceContext() for why membership is still re-checked on
    // every request regardless of this stored value. Not the same concept
    // as chatProjectId (a personal conversation-organization folder).
    workspaceId: {
      type: String,
      default: null,
      index: true,
    },
    // 8S5: the Agent version (1-indexed, i.e. `agent.versions.length` at the
    // moment this conversation first bound to `agent_id`) that governed this
    // conversation's behavior. Provenance only — later edits to the Agent
    // (which push new entries onto `agent.versions`) never change what this
    // conversation is attributed to. Set once at conversation creation and
    // immutable thereafter (same pattern as workspaceId above). `null`/
    // absent means either no agent_id, or a legacy pre-8S5 conversation
    // whose provenance was never recorded — both are handled as "unknown
    // provenance" by callers, not backfilled.
    agentVersion: {
      type: Number,
      default: null,
    },
    files: {
      type: [String],
    },
    expiredAt: {
      type: Date,
    },
    tenantId: {
      type: String,
      index: true,
    },
  },
  { timestamps: true },
);

convoSchema.index({ expiredAt: 1 }, { expireAfterSeconds: 0 });
convoSchema.index({ createdAt: 1, updatedAt: 1 });
convoSchema.index({ conversationId: 1, user: 1, tenantId: 1 }, { unique: true });
convoSchema.index({ user: 1, chatProjectId: 1, updatedAt: -1, _id: -1 });
convoSchema.index({ user: 1, chatProjectId: 1, createdAt: -1, _id: -1 });

convoSchema.index({ user: 1, isTemporary: 1, expiredAt: 1 });
// index for MeiliSearch sync operations
convoSchema.index({ _meiliIndex: 1, isTemporary: 1, expiredAt: 1 });

export default convoSchema;
