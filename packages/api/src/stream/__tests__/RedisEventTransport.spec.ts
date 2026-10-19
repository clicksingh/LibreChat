import type { Redis } from 'ioredis';
import { logger } from '@librechat/data-schemas';
import { RedisEventTransport } from '~/stream/implementations/RedisEventTransport';
import { createMockPublisher } from './helpers/publisher';

logger.silent = true;

function createMockSubscriber() {
  return {
    on: jest.fn(),
    subscribe: jest.fn().mockResolvedValue(undefined),
    unsubscribe: jest.fn().mockResolvedValue(undefined),
  };
}

function getMessageHandler(mockSubscriber: ReturnType<typeof createMockSubscriber>) {
  return mockSubscriber.on.mock.calls.find((call) => call[0] === 'message')?.[1] as (
    channel: string,
    message: string,
  ) => void;
}

describe('RedisEventTransport', () => {
  it('Aryn: recovers missing pubsub chunks from journal before terminal success', async () => {
    jest.useFakeTimers();
    try {
      const publisher = createMockPublisher();
      const subscriber = createMockSubscriber();
      const transport = new RedisEventTransport(publisher as unknown as Redis,
        subscriber as unknown as Redis);
      const got: string[] = [];
      const streamId = 'aryn-stream-journal-repair';
      transport.subscribe(streamId, {
        onChunk: (e) => got.push(String(e)),
        onDone: () => got.push('done'),
        onError: (e) => got.push('ERROR:' + e),
      });
      await transport.emitChunk(streamId, 'first');
      await transport.emitChunk(streamId, 'second');
      await transport.emitDone(streamId, { final: true });
      const handler = getMessageHandler(subscriber);
      // Redis pub/sub lost seq 0 and 1, but terminal seq 2 arrived.
      handler(`stream:{${streamId}}:events`,
        JSON.stringify({ type: 'done', seq: 2, data: { final: true } }));
      await jest.advanceTimersByTimeAsync(550);
      expect(got).toEqual(['first', 'second', 'done']);
      expect(publisher.hmget).toHaveBeenCalled();
      transport.destroy();
    } finally {
      jest.useRealTimers();
    }
  });

  it('Aryn: unrecoverable journal hole emits explicit interruption and never a false done', async () => {
    jest.useFakeTimers();
    try {
      const publisher = createMockPublisher();
      const subscriber = createMockSubscriber();
      const transport = new RedisEventTransport(publisher as unknown as Redis,
        subscriber as unknown as Redis);
      const got: string[] = [];
      const streamId = 'aryn-stream-journal-missing';
      transport.subscribe(streamId, {
        onChunk: () => got.push('chunk'),
        onDone: () => got.push('done'),
        onError: e => got.push(e),
      });
      // Deliberately reserve seq 0 without journaling or publishing it,
      // mimicking a crashed publisher after INCR.
      await publisher.incr(`stream:{${streamId}}:seq`);
      await transport.emitDone(streamId, { final: true }); // seq 1
      getMessageHandler(subscriber)(`stream:{${streamId}}:events`,
        JSON.stringify({ type: 'done', seq: 1, data: { final: true } }));
      await jest.advanceTimersByTimeAsync(1800);
      expect(got).toEqual([expect.stringContaining('STREAM_EVENT_GAP_UNRECOVERABLE')]);
      transport.destroy();
    } finally {
      jest.useRealTimers();
    }
  });

  it('resets stale abort-listener reorder state before the next real subscriber', async () => {
    const mockPublisher = createMockPublisher();
    const mockSubscriber = createMockSubscriber();
    const transport = new RedisEventTransport(
      mockPublisher as unknown as Redis,
      mockSubscriber as unknown as Redis,
    );

    const streamId = 'reorder-abort-listener-reuse-test';
    transport.onAbort(streamId, () => {});

    const messageHandler = getMessageHandler(mockSubscriber);
    const channel = `stream:{${streamId}}:events`;

    for (let i = 0; i < 5; i++) {
      await transport.emitChunk(streamId, { index: i });
      messageHandler(channel, JSON.stringify({ type: 'chunk', seq: i, data: { index: i } }));
    }

    await mockPublisher.del(`stream:{${streamId}}:seq`);

    const secondRunChunks: unknown[] = [];
    transport.subscribe(streamId, {
      onChunk: (event) => secondRunChunks.push(event),
    });

    messageHandler(channel, JSON.stringify({ type: 'chunk', seq: 0, data: { index: 0 } }));

    expect(secondRunChunks.map((chunk) => (chunk as { index: number }).index)).toEqual([0]);

    transport.destroy();
  });
});
