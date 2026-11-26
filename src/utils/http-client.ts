// MANINY DIGITAL — Minimal async HTTP/HTTPS client (Node.js built-ins only).
// Supports GET/HEAD requests with configurable timeout.

import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { URL } from 'node:url';
import type { HttpResponse } from '../types.js';

export interface RequestOptions {
  method?: 'GET' | 'HEAD' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  /** Follow up to N 3xx redirects. Default 2. */
  maxRedirects?: number;
}

const DEFAULT_TIMEOUT_MS = 7_000;
const USER_AGENT = 'MANINY-Security-Scanner/0.2.0';

/**
 * Perform a single HTTP/HTTPS request and return a normalised HttpResponse.
 * Network errors and timeouts produce a response with `error` set rather
 * than rejecting — callers check `error` before trusting other fields.
 */
export async function fetchUrl(
  urlStr: string,
  opts: RequestOptions = {}
): Promise<HttpResponse> {
  const start = Date.now();

  const result = await sendRequest(urlStr, opts, 0).catch(
    (err: unknown): HttpResponse => ({
      status: 0,
      headers: {},
      body: '',
      responseTimeMs: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    })
  );

  return result;
}

async function sendRequest(
  urlStr: string,
  opts: RequestOptions,
  redirectCount: number
): Promise<HttpResponse> {
  const start = Date.now();
  const {
    method = 'GET',
    headers: extraHeaders = {},
    body,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxRedirects = 2,
  } = opts;

  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    throw new Error(`Unparseable URL: ${urlStr}`);
  }

  const isHttps = parsed.protocol === 'https:';
  const transport = isHttps ? httpsRequest : httpRequest;

  const reqHeaders: Record<string, string> = {
    'User-Agent': USER_AGENT,
    Connection: 'close',
    ...extraHeaders,
  };

  if (body) {
    reqHeaders['Content-Length'] = String(Buffer.byteLength(body));
    reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
  }

  return new Promise((resolve, reject) => {
    const req = transport(
      {
        hostname: parsed.hostname,
        port: parsed.port
          ? Number(parsed.port)
          : isHttps
          ? 443
          : 80,
        path: parsed.pathname + parsed.search,
        method,
        headers: reqHeaders,
        // Allow self-signed certs during security assessments.
        rejectUnauthorized: false,
      },
      res => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', async () => {
          const responseTimeMs = Date.now() - start;
          const headers: Record<string, string | string[] | undefined> = {};

          for (const [k, v] of Object.entries(res.headers)) {
            headers[k.toLowerCase()] = v;
          }

          const statusCode = res.statusCode ?? 0;

          // Follow redirects
          const location = res.headers['location'];
          if (
            statusCode >= 300 &&
            statusCode < 400 &&
            typeof location === 'string' &&
            redirectCount < maxRedirects
          ) {
            const redirectUrl = location.startsWith('http')
              ? location
              : `${parsed.origin}${location}`;

            sendRequest(redirectUrl, opts, redirectCount + 1)
              .then(resolve)
              .catch(reject);
            return;
          }

          resolve({
            status: statusCode,
            headers,
            body: Buffer.concat(chunks).toString('utf-8'),
            responseTimeMs,
          });
        });

        res.on('error', reject);
      }
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Request timeout after ${timeoutMs}ms`));
    });

    req.on('error', reject);

    if (body) req.write(body);
    req.end();
  });
}
