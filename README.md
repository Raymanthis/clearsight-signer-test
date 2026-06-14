# ClearSight Storage Signer (Cloudflare Worker)

A ~90-line Cloudflare Worker that mints presigned upload/download URLs for **your
own** S3-compatible bucket, so ClearSight can store feedback media in your
infrastructure without ever holding your bucket keys (BYOS Strategy B, zero key
custody).

Although it runs on Cloudflare, it is **provider-agnostic** — point `S3_ENDPOINT`
at Cloudflare R2, Backblaze B2, Wasabi, MinIO, or AWS S3.

## How it works

ClearSight sends an HMAC-authenticated request (`X-CS-Signature` over the exact
body, ±60s replay window) asking for a presigned URL. The Worker enforces its own
guardrails regardless of what ClearSight asks for:

- **Prefix lock** — keys must live under `clearsight/` (allowlisted charset, no
  traversal, re-checked on the normalized path).
- **TTL cap** — presigned URLs expire in ≤ 900s.
- **Content pinning** — `PUT` URLs sign `Content-Type`/`Content-Length`, so size
  and type cannot be tampered.

Your bucket keys live only here; a compromise of ClearSight cannot escape these
guardrails or reach your storage directly.

## Deploy

### Option A — one-click (recommended)

Use the **Deploy to Cloudflare** button shown in ClearSight's storage settings
when you choose the S3-Compatible (Signer) option. Cloudflare clones this repo
and prompts you for the variables and secrets below. Generate the
`CS_SHARED_SECRET` value in ClearSight **first**, then paste it into the prompt.

### Option B — Wrangler CLI

```bash
npm install
# edit wrangler.toml [vars]: S3_ENDPOINT, BUCKET, S3_REGION
npx wrangler secret put S3_ACCESS_KEY
npx wrangler secret put S3_SECRET_KEY
npx wrangler secret put CS_SHARED_SECRET   # the value ClearSight showed you
npx wrangler deploy
```

### Option C — paste into the dashboard editor

If you can't use a terminal, `npm run bundle` produces a single self-contained
file at `dist/clearsight-signer.bundled.js` (no imports) that you can paste into
the Cloudflare dashboard's Worker editor, then set the vars/secrets under
Settings → Variables.

## Configuration

| Name | Kind | Notes |
|------|------|-------|
| `S3_ENDPOINT` | var | S3 API base (see examples in `wrangler.toml`) |
| `BUCKET` | var | bucket name |
| `S3_REGION` | var | `auto` for R2; the bucket region elsewhere |
| `S3_ACCESS_KEY` | secret | bucket token, Object Read & Write |
| `S3_SECRET_KEY` | secret | bucket token secret |
| `CS_SHARED_SECRET` | secret | shown once by ClearSight on save |

After deploying, paste the Worker's URL back into ClearSight and click **Test**.
