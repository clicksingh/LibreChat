import type { Document, Types } from 'mongoose';

export interface IModelPolicyPublication {
  _id?: Types.ObjectId;
  key: string;
  policyVersion: number;
  digest: string;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface IModelPolicyPublicationDocument
  extends Omit<IModelPolicyPublication, '_id'>,
    Document {}
