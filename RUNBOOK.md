# Jnvoy runbook

How to run Jnvoy day to day. Written for the person on call, who today is one person. Commands
assume `ADMIN_KEY` holds an admin key in your terminal (never paste keys into chat or tickets).

## 1. Is it up?

- `GET /health` needs no key. `"status": "healthy"` is normal. `"degraded"` means a database
  is configured but not working: scanning still works, but customer keys, usage counts and
  audit logs do not.
- Point an uptime monitor at `https://www.jnvoy.com/health`, alert on a failed request or on a
  response that does not contain `"status":"healthy"`, and send alerts to an address you read.
- Render shows deploys and logs for the service. Logs never contain request text.

## 2. Customers

Create (the key is shown once, so store it before closing the terminal):

    curl -s -X POST https://www.jnvoy.com/v1/admin/tenants -H "x-api-key: $ADMIN_KEY" \
      -H "Content-Type: application/json" \
      -d '{"company_name":"Acme Ltd","email":"security@acme.example","tier":"free"}'

Look at one or all:

    curl -s https://www.jnvoy.com/v1/admin/tenants -H "x-api-key: $ADMIN_KEY"
    curl -s https://www.jnvoy.com/v1/admin/tenants/TENANT_ID -H "x-api-key: $ADMIN_KEY"

Change plan, allowance or settings (takes effect within 30 seconds on every instance):

    curl -s -X PATCH https://www.jnvoy.com/v1/admin/tenants/TENANT_ID -H "x-api-key: $ADMIN_KEY" \
      -H "Content-Type: application/json" -d '{"tier":"production","policy":{"regions":"eu","judge":"off"}}'

Plans: `free` 10,000 calls a month, `production` 100,000, `business` 1,000,000, `enterprise`
unlimited. Add `"monthly_limit": N` for a custom allowance. A customer at the limit gets
`429 monthly_limit_reached`; raise the limit and they are served again straight away.

Switch a customer off (their key stops working at once; their audit log is kept):

    curl -s -X DELETE https://www.jnvoy.com/v1/admin/tenants/TENANT_ID -H "x-api-key: $ADMIN_KEY"

## 3. Keys

**A customer's key leaked or was lost.** Replace it. The old key stops working at once and the
new one is shown once:

    curl -s -X POST https://www.jnvoy.com/v1/admin/tenants/TENANT_ID/rotate-key -H "x-api-key: $ADMIN_KEY"

**An operator key (`JNVOY_API_KEYS`, `JNVOY_ADMIN_KEYS`) leaked.** Generate a new one:

    python3 -c "import secrets; print(secrets.token_urlsafe(32))"

In Render, set the variable to the new key (comma separated, no spaces, at least 24
characters each), save, and wait for the deploy. Removing the old key from the list revokes
it. If the variable ends up malformed, protected routes answer `503 auth_not_configured`:
fix the value and redeploy.

**A provider key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) leaked.** Revoke it in the provider's
console first, then put the new one in Render.

## 4. Data and backups

What is stored: per request, only counts of what was found (by type), the provider, model,
latency, the customer id and a short key fingerprint. Never prompt text, never replies. See
`/privacy`. The tenants table holds customer names, contact emails, plans and hashed keys.

Backups are the database host's job. Check, in the Render dashboard for the Postgres
instance, that backups are on for your plan and note the retention. Some free database plans
are deleted after a set period, so confirm the plan before real customers rely on it.

Take your own copy now and then (needs the `DATABASE_URL`, which stays in your terminal):

    pg_dump "$DATABASE_URL" --no-owner -Fc -f jnvoy_$(date +%Y%m%d).dump

Practise restoring into a scratch database at least once, before you need to:

    createdb jnvoy_restore_test
    pg_restore --no-owner -d jnvoy_restore_test jnvoy_20260101.dump

## 5. Deploys and rollback

Pushing to `main` deploys. If a deploy misbehaves, use Render's "Rollback" to the last good
deploy, then fix forward. Run `pytest -q` before every push.

## 6. Something is wrong

1. Check `/health` and Render's deploy status and logs.
2. `401` for everyone: operator keys changed or are malformed (section 3). `503` with
   `auth_not_configured`: same. `429 monthly_limit_reached` for one customer: expected,
   raise the limit if they should have more.
3. Slow responses: the optional second check (`JNVOY_JUDGE_BACKEND`) adds about a second.
   If its provider is down, `JNVOY_JUDGE_FAIL_MODE=open` (default) keeps first-pass redaction.
4. Model errors (`502`, provider errors): the provider is the problem. `/v1/providers/health`
   (admin key) shows recent failures.
5. Tell affected customers what happened, what data was involved (usually none: only counts
   are stored), and when it was fixed. Keep a short written note of each incident.

## 7. Known limits, to tell customers honestly

- The hosted service receives original text before redacting it, in memory only. Customers who
  cannot accept that should self-host.
- Detection is strong but not guaranteed complete. Names are detected best in English.
- One worker per container: the cache and per-minute rate limit are in memory. Scale with more
  containers only after a shared limiter exists.
