const DEFAULT_SSE_TRANSPORT_HEARTBEAT_MS = 15_000;

function createSseTransportHeartbeat(res, intervalMs = DEFAULT_SSE_TRANSPORT_HEARTBEAT_MS) {
  let stopped = false;
  let timer;
  const stop = () => {
    if (stopped) {
      return;
    }
    stopped = true;
    if (timer) {
      clearInterval(timer);
    }
  };

  timer = setInterval(() => {
    if (res.destroyed || res.writableEnded) {
      stop();
      return;
    }
    try {
      res.write(': cbhr-transport-keepalive\n\n');
      if (typeof res.flush === 'function') {
        res.flush();
      }
    } catch {
      stop();
    }
  }, intervalMs);

  timer.unref?.();
  res.once?.('close', stop);
  res.once?.('finish', stop);
  return stop;
}

module.exports = {
  DEFAULT_SSE_TRANSPORT_HEARTBEAT_MS,
  createSseTransportHeartbeat,
};
