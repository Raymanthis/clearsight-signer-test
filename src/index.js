/**
 * ClearSight customer-hosted signer (BYOS Strategy B, FR-2.3). Hosted on a
 * Cloudflare Worker, but provider-agnostic: it signs presigned URLs for ANY
 * S3-compatible endpoint (Cloudflare R2, Backblaze B2, Wasabi, MinIO, AWS S3).
 *
 * Deployed in the CUSTOMER's own account. It holds the bucket keys as its own
 * secrets; ClearSight never sees them. ClearSight authenticates each request with
 * an HMAC over the exact body (the CS_SHARED_SECRET), and the signer enforces its
 * OWN guardrails — prefix lock + TTL cap — so even a compromised ClearSight cannot
 * escape the `clearsight/` prefix or mint long-lived URLs.
 *
 * Request  (POST, from ClearSight's RemoteSignerStrategy):
 *   headers: X-CS-Signature: <hex hmac-sha256 of the raw body>
 *   body:    {"action":"put|get|head","key":"clearsight/…","mime":…,"size":…,"ttl":…,"ts":…,"nonce":…}
 * Response: {"url":"<presigned url>"}
 *
 * Secrets (set via `wrangler secret put`, or the deploy-button prompt):
 *   S3_ACCESS_KEY, S3_SECRET_KEY  — a bucket API key scoped to Object Read & Write
 *   CS_SHARED_SECRET              — the value ClearSight shows once on save
 * Vars (wrangler.toml [vars]):
 *   S3_ENDPOINT  — the S3 API base, e.g.
 *                  https://<account>.r2.cloudflarestorage.com   (Cloudflare R2)
 *                  https://s3.us-west-002.backblazeb2.com        (Backblaze B2)
 *                  https://s3.wasabisys.com                      (Wasabi)
 *   BUCKET       — the bucket name
 *   S3_REGION    — signing region; "auto" for R2, the bucket's region elsewhere
 */
import { AwsClient } from 'aws4fetch';

const PREFIX = 'clearsight/';
const MAX_TTL = 900; // seconds — hard cap, independent of what ClearSight requests

// Object keys ClearSight mints are ULID/path segments under clearsight/. Anything
// else is rejected: the signer is a trust boundary against a compromised
// ClearSight, so a raw startsWith() is not enough — `clearsight/../secret` would
// pass it and then `new URL()` would normalize the `..` away and escape the
// prefix. Restrict to a safe charset and reject traversal/empty segments outright.
const KEY_PATTERN = /^clearsight\/[A-Za-z0-9._\-/]+$/;

function isSafeKey(key) {
    return (
        typeof key === 'string' &&
        KEY_PATTERN.test(key) &&
        !key.includes('..') && // no parent-directory traversal
        !key.includes('//') && // no empty segments
        !key.endsWith('/') // must name an object, not a "folder"
    );
}

async function hmacHex(secret, message) {
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const signature = await crypto.subtle.sign(
        'HMAC',
        key,
        new TextEncoder().encode(message),
    );

    return [...new Uint8Array(signature)]
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

/** Constant-time string compare to avoid leaking the signature byte-by-byte. */
function safeEqual(a, b) {
    if (
        typeof a !== 'string' ||
        typeof b !== 'string' ||
        a.length !== b.length
    ) {
        return false;
    }

    let diff = 0;

    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return diff === 0;
}

export default {
    async fetch(request, env) {
        if (request.method !== 'POST') {
            return new Response('method not allowed', { status: 405 });
        }

        const body = await request.text();

        // 1) Authenticate ClearSight: HMAC over the EXACT body.
        const expected = await hmacHex(env.CS_SHARED_SECRET, body);

        if (!safeEqual(request.headers.get('x-cs-signature') ?? '', expected)) {
            return new Response('unauthorized', { status: 401 });
        }

        let payload;

        try {
            payload = JSON.parse(body);
        } catch {
            return new Response('bad request', { status: 400 });
        }

        const { action, key, mime, size, ttl, ts } = payload;

        // 2) Replay window: reject requests more than 60s out of sync.
        if (Math.abs(Date.now() / 1000 - Number(ts)) > 60) {
            return new Response('stale request', { status: 401 });
        }

        // 3) Guardrails the signer enforces regardless of ClearSight.
        if (!isSafeKey(key)) {
            return new Response('forbidden key', { status: 403 });
        }

        const method = { put: 'PUT', get: 'GET', head: 'HEAD' }[action];

        if (!method) {
            return new Response('bad action', { status: 400 });
        }

        const expires = Math.min(Number(ttl) || 600, MAX_TTL);

        const aws = new AwsClient({
            accessKeyId: env.S3_ACCESS_KEY,
            secretAccessKey: env.S3_SECRET_KEY,
            service: 's3',
            region: env.S3_REGION || 'auto',
        });

        // Percent-encode each segment, then re-assert the prefix on the NORMALIZED
        // pathname — the only check that sees exactly what the provider receives.
        // Path-style addressing ({endpoint}/{bucket}/{key}) is used uniformly: it
        // works across R2/B2/Wasabi/MinIO without per-provider host juggling.
        const endpoint = env.S3_ENDPOINT.replace(/\/+$/, '');
        const encodedKey = key.split('/').map(encodeURIComponent).join('/');
        const url = new URL(`${endpoint}/${env.BUCKET}/${encodedKey}`);

        if (!url.pathname.startsWith(`/${env.BUCKET}/${PREFIX}`)) {
            return new Response('forbidden key', { status: 403 });
        }

        url.searchParams.set('X-Amz-Expires', String(expires));

        // For PUT, pin Content-Type/Content-Length into the signature so size/type
        // cannot be tampered (mirrors ClearSight's EnforcingS3SignatureV4).
        const headers =
            action === 'put'
                ? {
                      'content-type': mime || 'application/octet-stream',
                      'content-length': String(size ?? 0),
                  }
                : {};

        const signed = await aws.sign(url.toString(), {
            method,
            headers,
            aws: { signQuery: true },
        });

        return Response.json({ url: signed.url });
    },
};
