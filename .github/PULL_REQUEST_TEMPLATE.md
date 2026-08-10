## Objective

Describe the CRM behavior this change adds or fixes.

## Evidence

- Exact source revision:
- Test output (`npm test`):
- Negative paths exercised (missing/invalid key, unset ECHO_API_KEY):
- Hosted CI run:

## Security and release impact

- [ ] No secrets (`ECHO_API_KEY`, `STRIPE_SECRET_KEY`) or real customer/contact data are included.
- [ ] `PUBLIC_PATHS` is unchanged, or any addition is called out explicitly and justified.
- [ ] Staging-first deployment and rollback implications are documented.
