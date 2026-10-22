import { Model } from 'mongoose';
import { applyTenantIsolation } from '~/models/plugins/tenantIsolation';
import challengeSchema, { IChallenge } from '~/schema/challenge';

export function createChallengeModel(mongoose: typeof import('mongoose')): Model<IChallenge> {
  applyTenantIsolation(challengeSchema);
  return (
    mongoose.models.Challenge ||
    mongoose.model<IChallenge>('Challenge', challengeSchema, 'challenges')
  );
}
