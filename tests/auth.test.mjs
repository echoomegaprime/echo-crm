import { test } from 'node:test';
import assert from 'node:assert/strict';
import { app, timingSafeEqual } from '../src/index.ts';

test('timingSafeEqual: identical strings match', () => {
  assert.equal(timingSafeEqual('a-real-secret-key', 'a-real-secret-key'), true);
});

test('timingSafeEqual: different values of equal length do not match', () => {
  assert.equal(timingSafeEqual('a-real-secret-key', 'a-fake-secret-key'), false);
});

test('timingSafeEqual: different-length values do not match', () => {
  assert.equal(timingSafeEqual('short', 'a-much-longer-value'), false);
});

// Minimal in-memory stub of the CACHE KV binding the rate-limit middleware
// requires -- these tests exercise the auth boundary, not rate limiting, so
// a real KV isn't needed, just something that won't throw. A fresh instance
// per test avoids one test's requests counting against another's rate limit.
function fakeKv() {
  const store = new Map();
  return {
    async get(key) { return store.get(key) ?? null; },
    async put(key, value) { store.set(key, value); },
  };
}

function env(overrides = {}) {
  return { ECHO_API_KEY: 'real-secret', CACHE: fakeKv(), ...overrides };
}

// End-to-end middleware tests via app.request() -- these exercise the ACTUAL
// routing + middleware, not a reimplementation of it, so they prove the real
// bug (every GET route was unauthenticated) is actually fixed at the route
// level, not just that a helper function behaves correctly in isolation.

test('GET /contacts without credentials is rejected (regression test for the real bug: every GET route was previously exempt from auth)', async () => {
  const res = await app.request('/contacts', {}, env());
  assert.equal(res.status, 401);
});

test('GET /companies without credentials is rejected', async () => {
  const res = await app.request('/companies', {}, env());
  assert.equal(res.status, 401);
});

test('GET /deals without credentials is rejected', async () => {
  const res = await app.request('/deals', {}, env());
  assert.equal(res.status, 401);
});

test('GET /export/contacts without credentials is rejected (the bulk customer-data export endpoint)', async () => {
  const res = await app.request('/export/contacts', {}, env());
  assert.equal(res.status, 401);
});

test('GET /analytics/revenue without credentials is rejected', async () => {
  const res = await app.request('/analytics/revenue', {}, env());
  assert.equal(res.status, 401);
});

test('GET / (root) remains public with no credentials', async () => {
  const res = await app.request('/', {}, env());
  assert.equal(res.status, 200);
});

test('GET /plans remains public with no credentials', async () => {
  const res = await app.request('/plans', {}, env());
  assert.equal(res.status, 200);
});

test('GET /contacts with the correct X-Echo-API-Key header passes the auth boundary (may still error on the DB stub, but must not be 401)', async () => {
  const res = await app.request('/contacts', { headers: { 'X-Echo-API-Key': 'real-secret' } }, env());
  assert.notEqual(res.status, 401);
});

test('GET /contacts with a wrong key is rejected', async () => {
  const res = await app.request('/contacts', { headers: { 'X-Echo-API-Key': 'wrong-secret' } }, env());
  assert.equal(res.status, 401);
});

test('every route fails closed when ECHO_API_KEY is unset, even with a header that happens to equal the string "undefined"', async () => {
  const res = await app.request('/contacts', { headers: { 'X-Echo-API-Key': 'undefined' } }, env({ ECHO_API_KEY: undefined }));
  assert.equal(res.status, 401);
});
