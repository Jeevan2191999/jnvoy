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

Backups are the database host's job. In the Render dashboard, open the Postgres instance and its
Recovery tab. Point-in-time recovery covers the last 3 days on the current plan. Logical exports
are made on demand ("Create export"); Render keeps each one for at least 7 days. Nothing is
exported automatically, so make one before any risky change.

The database accepts connections only from the Jnvoy service, on Render's private network, so
`pg_dump` from your laptop cannot reach it. That is deliberate. Use the dashboard instead.

**Practise a restore once, before a customer relies on it.** This was last done on 26 October 2026
and worked: the data came back with the expected row counts. It uses an export and your own
machine, and changes nothing in production:

1. Render dashboard, the Postgres instance, Recovery tab, Export: "Create export", then download
   the file (it is a `.dir.tar.gz`).
2. Unpack it into a new folder and restore it into a scratch database, with PostgreSQL installed
   (Postgres.app on a Mac; add its `bin` folder to your PATH):

       mkdir -p ~/restore_test && tar -xzf ~/Downloads/THE_FILE.dir.tar.gz -C ~/restore_test
       ls -R ~/restore_test
       createdb jnvoy_restore_test
       pg_restore --no-owner -d jnvoy_restore_test ~/restore_test/THE_FOLDER/jnvoy

3. Check it: `psql jnvoy_restore_test -c "select count(*) from audit_log;"` and the same for
   `tenants` and `api_key_usage`. Counts should look right.
4. Clean up, because the export holds customer details:

       dropdb jnvoy_restore_test
       rm -rf ~/restore_test ~/Downloads/THE_FILE.dir.tar.gz

For a real incident, "Restore" in the Recovery tab creates a new database from a chosen time.
Point `DATABASE_URL` in Render at the new one (use its internal hostname), save, and wait for the
deploy. Write down the time you restored to.

## 5. Deploys and rollback

Pushing to `main` deploys, once the GitHub tests pass (Render: the web service, Settings, Build
and Deploy, Auto-Deploy "After CI Checks Pass"). If a deploy misbehaves, use Render's "Rollback"
to the last good deploy, then fix forward. Run `pytest -q` before every push.

Every response carries an `x-request-id` header. Ask a customer for it when they report a problem,
then search Render's logs for it. It identifies one request and contains none of their text.

### Keeping dependencies up to date (about 15 minutes a month)

Every version is pinned: `requirements.txt` names what we use directly, and `constraints.txt` pins
everything else. Nothing changes on its own.

- **Monthly, automatic.** On the 1st of each month the `refresh-pins` workflow installs the newest
  versions of everything we do not name, runs the full tests on them, and opens a pull request
  "Refresh pinned dependency versions" only if the tests pass. Read the version list in the pull
  request, merge it, and the usual checks and deploy follow. To run it now: GitHub, Actions,
  refresh-pins, "Run workflow". It needs Settings, Actions, General, "Allow GitHub Actions to
  create and approve pull requests" switched on; otherwise take the new file from the run's
  "constraints" artifact.
- **A package we name directly** (FastAPI, spaCy, Presidio and so on) is changed by hand: edit its
  version in `requirements.txt`, run the refresh workflow or `pip freeze | python
  scripts/refresh_constraints.py > constraints.txt` in a clean Python 3.12 environment, run
  `pytest -q`, and push. Change spaCy only together with re-measuring the accuracy page.
- **A security alert** from GitHub: do the same for that package, promptly.
- If a merge breaks the deploy, Render keeps the previous version running; roll back the commit.

## 6. Something is wrong

1. Check `/health` and Render's deploy status and logs.
2. `401` for everyone: operator keys changed or are malformed (section 3). `503` with
   `auth_not_configured`: same. `429 monthly_limit_reached` for one customer: expected,
   raise the limit if they should have more.
3. Slow responses: very large requests are slower to scan (the limit is `JNVOY_MAX_BODY_BYTES`,
   default about 256 KB). The second check (`JNVOY_JUDGE_BACKEND`) is off on the hosted service.
   If you switch it on and its provider is down, `JNVOY_JUDGE_FAIL_MODE=open` (default) keeps
   first-pass redaction.
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
