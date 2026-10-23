import { useEffect, useState } from 'react';

/**
 * A ticking `Date.now()` for the panel's countdowns.
 *
 * One interval per panel keeps every timer on the same tick and avoids drift: components derive
 * remaining time from `deadline - now` instead of decrementing their own counters.
 */
export function useNow(intervalMs: number = 1000): number {
  const [now, setNow] = useState<number>(() => Date.now());

  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);

  return now;
}
