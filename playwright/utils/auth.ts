/**
 * 8S3C.1 browser E2E — safe authenticated state (session injection).
 *
 * Creates the exact `sessions` document POST /api/auth/login produces, then
 * injects the matching refreshToken cookie. The client's silent-refresh
 * exchanges it for an access token. NO password, NO /api/auth/login calls —
 * this never trips the LibreChat login rate-limiter ban.
 *
 * `user` is stored in `messages` as a hex string; `sessions.user` is an
 * ObjectId (matches the real login path).
 */

import { MongoClient, ObjectId } from 'mongodb';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { HOST_ENV } from './constants';

const env = fs.readFileSync(HOST_ENV, 'utf8');
const get = (k: string) => (env.match(new RegExp(`^${k}=(.*)$`, 'm')) || [])[1]?.trim();
const JWT_REFRESH_SECRET = get('JWT_REFRESH_SECRET');
if (!JWT_REFRESH_SECRET) {
  throw new Error('[auth] JWT_REFRESH_SECRET not found in LibreChat .env');
}
export const MONGO_URI = (get('MONGO_URI') || '')
  .replace('mongodb://mongodb:', 'mongodb://172.18.0.2:')
  .replace('mongodb://mongo:', 'mongodb://172.18.0.2:');

export interface SessionState {
  refreshToken: string;
  sessionId: string;
}

/** Mint a LibreChat access token exactly as the server does (JWT_SECRET). */
export function accessToken(userId: string): string {
  const secret = get('JWT_SECRET');
  if (!secret) {
    throw new Error('[auth] JWT_SECRET not found in LibreChat .env');
  }
  return jwt.sign({ id: userId }, secret, { expiresIn: 300 });
}

export async function createSession(userId: string): Promise<SessionState> {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  try {
    const db = client.db('LibreChat');
    const sessionId = new ObjectId();
    const expiration = new Date(Date.now() + 1000 * 60 * 60 * 24);
    const refreshToken = jwt.sign(
      { id: userId, sessionId: sessionId.toString() },
      JWT_REFRESH_SECRET,
      { expiresIn: 24 * 60 * 60 },
    );
    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    await db.collection('sessions').insertOne({
      _id: sessionId,
      user: new ObjectId(userId),
      refreshTokenHash,
      expiration,
    });
    return { refreshToken, sessionId: sessionId.toString() };
  } finally {
    await client.close();
  }
}

export async function cleanupSession(sessionId: string): Promise<void> {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  try {
    await client.db('LibreChat').collection('sessions').deleteOne({ _id: new ObjectId(sessionId) });
  } finally {
    await client.close();
  }
}

/** The refreshToken cookie a real login setAuthTokens() would have stored. */
export function refreshTokenCookie(refreshToken: string) {
  return [
    {
      name: 'refreshToken',
      value: refreshToken,
      domain: new URL(process.env.LC_BASE ?? 'http://127.0.0.1:3080').hostname,
      path: '/',
      httpOnly: true,
      secure: false,
      sameSite: 'Strict' as const,
    },
  ];
}
