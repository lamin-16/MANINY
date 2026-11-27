// MANINY DIGITAL — Per-host rate limiter.
// Prevents hammering a single host while allowing parallel probes across different hosts.

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export class RateLimiter {
  private readonly lastRequestAt = new Map<string, number>();
  private readonly delayMs: number;

  /**
   * @param delayMs Minimum milliseconds between consecutive requests to the same host.
   *                Default 300 ms — polite but not slow.
   */
  constructor(delayMs = 300) {
    this.delayMs = Math.max(0, delayMs);
  }

  /**
   * Wait until the per-host delay has elapsed since the last request to that host.
   * Call this immediately before every outgoing HTTP request.
   */
  async throttle(host: string): Promise<void> {
    if (this.delayMs === 0) return;

    const last = this.lastRequestAt.get(host) ?? 0;
    const elapsed = Date.now() - last;

    if (elapsed < this.delayMs) {
      await sleep(this.delayMs - elapsed);
    }

    this.lastRequestAt.set(host, Date.now());
  }

  /** Mark a request as sent now (without sleeping). */
  mark(host: string): void {
    this.lastRequestAt.set(host, Date.now());
  }

  static unlimited(): RateLimiter {
    return new RateLimiter(0);
  }
}
