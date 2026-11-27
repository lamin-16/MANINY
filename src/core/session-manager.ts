// MANINY DIGITAL — Session manager: cookie jar, Bearer token, custom headers.

import type { SessionConfig } from '../types.js';

export class SessionManager {
  private readonly cookieJar = new Map<string, string>();
  private readonly config: SessionConfig;

  constructor(config: SessionConfig) {
    this.config = config;
    for (const [name, value] of Object.entries(config.cookies)) {
      this.cookieJar.set(name, value);
    }
  }

  /**
   * Absorb Set-Cookie headers from a response into the in-memory jar.
   * Never persists to disk — scan-scoped only.
   */
  updateFromSetCookie(values: string | string[] | undefined): void {
    const list = Array.isArray(values) ? values : values ? [values] : [];
    for (const raw of list) {
      const nameValue = raw.split(';')[0] ?? '';
      const eqIndex   = nameValue.indexOf('=');
      if (eqIndex === -1) continue;
      const name  = nameValue.slice(0, eqIndex).trim();
      const value = nameValue.slice(eqIndex + 1).trim();
      if (name) this.cookieJar.set(name, value);
    }
  }

  /** Build the full set of outgoing request headers for this session. */
  buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = { ...this.config.customHeaders };

    if (this.config.bearerToken) {
      headers['Authorization'] = `Bearer ${this.config.bearerToken}`;
    }

    if (this.cookieJar.size > 0) {
      headers['Cookie'] = [...this.cookieJar.entries()]
        .map(([k, v]) => `${k}=${v}`)
        .join('; ');
    }

    return headers;
  }

  get hasBearerToken(): boolean {
    return !!this.config.bearerToken;
  }

  get hasCookies(): boolean {
    return this.cookieJar.size > 0;
  }

  static empty(): SessionManager {
    return new SessionManager({ cookies: {}, customHeaders: {} });
  }
}
