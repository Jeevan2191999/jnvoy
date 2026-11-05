# Security

## Reporting a vulnerability

Email **j.nagaraj2109@gmail.com** with the subject "Jnvoy security". Please do not open a public issue for a security problem.

Include what you found, how to reproduce it, and what you think the impact is. Testing against your own deployment is fine.

## What to expect

- I will acknowledge your report within two working days and tell you what I find.
- If the problem affects customers, I will tell them without undue delay.
- When it is fixed I will tell you, and I will name you in the notice if you want to be named.
- Jnvoy is run by one person and does not pay rewards for reports.

## Rules for testing the hosted service

In scope: `www.jnvoy.com` and the code in this repository.

Please do not:

- access, change or delete another customer's data (if you reach it by accident, stop and tell me),
- run denial-of-service or load tests against the hosted service,
- test social engineering, or physical access,
- test other people's systems that Jnvoy talks to, such as model providers or Render.

If you follow these rules and act in good faith, I will not take action against you for your research.

## What Jnvoy does and does not do

- The [security page](https://www.jnvoy.com/security) and the [privacy page](https://www.jnvoy.com/privacy) list the services involved, what is stored, and what has not been done yet, including that there is no SOC 2 or ISO 27001 report and no independent penetration test.
- [THREAT_MODEL.md](THREAT_MODEL.md) lists the ways Jnvoy can go wrong, what stops each, the test that shows it, and what is left. If you find one that is missing, that is a useful report.
- The [accuracy page](https://www.jnvoy.com/accuracy) gives the measured limits of the detection. A value Jnvoy does not find is a documented limit, not a vulnerability, unless you can show it fails in a way the page says it does not.

## Supported versions

Only the latest release on `main` is supported.
