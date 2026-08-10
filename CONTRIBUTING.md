# Contributing

Thank you for improving Echo CRM. This is a public, proprietary infrastructure project:
contributions are welcome for review, but repository visibility does not grant a general use or
redistribution license.

## Development path

1. Open an issue describing the CRM behavior being changed.
2. Create a focused branch from current `main`.
3. Add a failing test before changing authentication or the `PUBLIC_PATHS` allowlist -- see
   `tests/auth.test.mjs`'s end-to-end middleware tests, which exercise real routes via
   `app.request()`, not a reimplementation of the middleware.
4. Validate before opening a pull request:

   ```powershell
   npm install
   npm test
   ```

5. Open a pull request using the repository template and include exact test output.

## Pull-request requirements

- No secrets (`ECHO_API_KEY`, `STRIPE_SECRET_KEY`) or real customer/contact data are included.
- No stubs, placeholders, skipped security checks, or self-asserted readiness.
- Any addition to `PUBLIC_PATHS`, or any change to the authentication boundary, is called out
  explicitly in the pull request description and justified (this repo's history includes a real
  incident where the entire read surface was accidentally public -- treat every allowlist change
  as security-sensitive).
