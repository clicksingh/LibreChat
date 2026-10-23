/**
 * W10 — device-policy INTERNAL types (not part of the public shape).
 *
 * The primitives port a test hands the resolver, and the normal forms the resolver reads.
 * Kept in a separate module so `resolver.ts` stays readable and `primitives.ts` (the design note)
 * does not need to know how the normal forms are built.
 */

import type {
  DeviceCapabilityPolicyPrimitives,
  DeviceToolRegistryPrimitives,
} from './primitives';

/** The author of a resolution row: the four levels, server law, or no data at all. */
export type DevicePolicyDeniedBy = 'user' | 'group' | 'role' | 'tenant' | 'law' | 'none';

/** The primitive port the resolver consumes (see `primitives.ts` for the contract). */
export type DevicePolicyPrimitivesLike = {
  capabilityPolicy: DeviceCapabilityPolicyPrimitives;
  toolRegistry: DeviceToolRegistryPrimitives;
};

/** A stored scope, read defensively and normalised to one usable shape. */
export type NormalizedToolScope = {
  shape: 'valid' | 'malformed';
  id: string | null;
  name: string | null;
  stage: string | null;
  isActive: boolean;
  tools: string[];
  version: number;
  updatedAt: Date | null;
  /** How many entries the stored `tools` value carried before cleaning. */
  listedCount: number;
};

export type { DevicePolicyPrimitivesLike };