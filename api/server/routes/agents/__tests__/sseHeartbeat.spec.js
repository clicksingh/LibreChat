const { createSseTransportHeartbeat } = require('../sseHeartbeat');

describe('client-facing SSE transport heartbeat', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('writes protocol-valid SSE comments without application events', () => {
    const listeners = {};
    const res = {
      destroyed: false,
      writableEnded: false,
      write: jest.fn(),
      flush: jest.fn(),
      once: jest.fn((event, handler) => {
        listeners[event] = handler;
      }),
    };

    createSseTransportHeartbeat(res, 1000);
    jest.advanceTimersByTime(3000);

    expect(res.write).toHaveBeenCalledTimes(3);
    expect(res.write).toHaveBeenNthCalledWith(1, ': cbhr-transport-keepalive\n\n');
    expect(res.flush).toHaveBeenCalledTimes(3);

    listeners.close();
    jest.advanceTimersByTime(2000);
    expect(res.write).toHaveBeenCalledTimes(3);
  });

  it('stops itself when the response is already closed', () => {
    const res = {
      destroyed: true,
      writableEnded: false,
      write: jest.fn(),
      once: jest.fn(),
    };

    createSseTransportHeartbeat(res, 1000);
    jest.advanceTimersByTime(2000);

    expect(res.write).not.toHaveBeenCalled();
  });
});
