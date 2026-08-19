import type { TConversation, TEndpointOption } from 'librechat-data-provider';
import type { IUser, AppConfig } from '@librechat/data-schemas';
import type { Request } from 'express';

/**
 * LibreChat-specific request body type that extends Express Request body
 * (have to use type alias because you can't extend indexed access types like Request['body'])
 */
export type RequestBody = {
  messageId?: string;
  fileTokenLimit?: number;
  conversationId?: string;
  parentMessageId?: string;
  endpoint?: string;
  endpointType?: string;
  model?: string;
  key?: string;
  endpointOption?: Partial<TEndpointOption>;
};

export type ServerRequest = Request<unknown, unknown, RequestBody> & {
  user?: IUser;
  config?: AppConfig;
  /** Server-captured conversation creation time used to anchor dynamic prompt variables. */
  conversationCreatedAt?: string;
  /** Conversation loaded while resolving the prompt timestamp anchor, reused by save logic. */
  resolvedConversation?: Partial<TConversation> | null;
  /** Passport strategy that populated req.user for this request. */
  authStrategy?: string;
  /** 8S3D.1: resolved+re-checked project workspace for this request's code
   * execution/file operations (undefined = personal workspace, the default).
   * Set by resolveWorkspaceContext() — never trust a value set any other way. */
  workspaceContext?: { kind: 'project'; workspaceId: string };
};
