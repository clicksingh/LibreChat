export interface MockPublisher {
  publish: jest.Mock;
  hset: jest.Mock;
  hmget: jest.Mock;
  incr: jest.Mock;
  expire: jest.Mock;
  ttl: jest.Mock;
  get: jest.Mock;
  set: jest.Mock;
  del: jest.Mock;
  eval: jest.Mock;
}

/** Mock publisher with Redis command simulation for atomic sequence counters */
export function createMockPublisher(): MockPublisher {
  const counters = new Map<string, number>();
  const journals = new Map<string, Map<string, string>>();
  const values = new Map<string, string>();
  const ttls = new Map<string, number>();
  const publisher: MockPublisher = {
    publish: jest.fn().mockResolvedValue(1),
    hset: jest.fn().mockImplementation(async (key: string, field: string, payload: string) => {
      if (!journals.has(key)) journals.set(key, new Map());
      journals.get(key)!.set(field, payload);
      return 1;
    }),
    hmget: jest
      .fn()
      .mockImplementation(async (key: string, ...fields: string[]) =>
        fields.map((f) => journals.get(key)?.get(f) ?? null),
      ),

    incr: jest.fn().mockImplementation((key: string) => {
      const current = (counters.get(key) ?? 0) + 1;
      counters.set(key, current);
      return Promise.resolve(current);
    }),
    expire: jest.fn().mockImplementation((key: string, ttl: number) => {
      if (!counters.has(key)) {
        return Promise.resolve(0);
      }
      ttls.set(key, ttl);
      return Promise.resolve(1);
    }),
    ttl: jest.fn().mockImplementation((key: string) => {
      if (!counters.has(key)) {
        return Promise.resolve(-2);
      }
      return Promise.resolve(ttls.get(key) ?? -1);
    }),
    get: jest.fn().mockImplementation((key: string) => {
      const stored = values.get(key);
      if (stored != null) {
        return Promise.resolve(stored);
      }
      const val = counters.get(key);
      return Promise.resolve(val != null ? String(val) : null);
    }),
    set: jest.fn().mockImplementation((key: string, value: string) => {
      values.set(key, value);
      return Promise.resolve('OK');
    }),
    del: jest.fn().mockImplementation((...keys: string[]) => {
      for (const key of keys) {
        counters.delete(key);
        values.delete(key);
        ttls.delete(key);
      }
      return Promise.resolve(keys.length);
    }),
    eval: jest.fn(),
  };

  /**
   * Stands in for PUBLISH_SEQ_LUA, which allocates the sequence and publishes in one server-side
   * round trip. Delegates to the incr/publish mocks rather than reimplementing them, so a test
   * can still fail either half independently and observe the ordering between them.
   */
  publisher.eval.mockImplementation(
    async (_script: string, numKeys: number, ...parts: string[]) => {
      const keys = parts.slice(0, numKeys);
      const args = parts.slice(numKeys);
      const [channel, prefix, suffix, ttlSeconds] = args;
      const seqKey = keys[0];
      const jobKey = keys[1];
      const journalKey = keys[numKeys - 1];
      const count = numKeys === 4 ? Number(args[8]) : 1;
      const generationId = numKeys === 4 ? args[9] : '';
      const batch = numKeys === 4 ? args.slice(10) : [];
      let last = 0;
      for (let i = 0; i < count; i++) last = (await publisher.incr(seqKey)) as number;
      const seq = last - count;
      let ttl = Number(ttlSeconds);
      const existing = (await publisher.ttl(seqKey)) as number;
      if (existing < Math.floor(ttl / 2)) {
        const jobTtl = (await publisher.ttl(jobKey)) as number;
        if (jobTtl > ttl) ttl = jobTtl;
        await publisher.expire(seqKey, ttl);
      }
      const frame = `${prefix}${seq}${suffix}`;
      for (let i = 0; i < count; i++) {
        let payload = frame;
        if (count > 1) {
          const event = batch[i];
          payload = `{"type":"chunk","seq":${seq + i},"data":${event}${generationId ? `,"generationId":${generationId}` : ''}}`;
        }
        await publisher.hset(journalKey, String(seq + i), payload);
      }
      await publisher.publish(channel, frame);
      return seq;
    },
  );

  return publisher;
}
