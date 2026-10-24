// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

/** Small in-memory LRU cache with TTL. Map keeps insertion order, so the first key is the oldest. */
class TtlCache {
  constructor({ maxEntries, ttlMs }) {
    this.maxEntries = maxEntries;
    this.ttlMs = ttlMs;
    this.map = new Map();
  }

  get(key) {
    const hit = this.map.get(key);
    if (!hit) return undefined;
    if (hit.expires < Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    this.map.delete(key);
    this.map.set(key, hit);
    return hit.value;
  }

  set(key, value) {
    this.map.delete(key);
    this.map.set(key, { value, expires: Date.now() + this.ttlMs });
    while (this.map.size > this.maxEntries) this.map.delete(this.map.keys().next().value);
  }

  get size() {
    return this.map.size;
  }
}

/** Caps concurrent scans and the waiting queue so one client cannot exhaust the server. */
class Limiter {
  constructor({ maxActive, maxQueued }) {
    this.maxActive = maxActive;
    this.maxQueued = maxQueued;
    this.active = 0;
    this.queue = [];
  }

  /** Returns false when the queue is full. */
  async run(fn) {
    if (this.active >= this.maxActive) {
      if (this.queue.length >= this.maxQueued) return { rejected: true };
      await new Promise((resolve) => this.queue.push(resolve));
    }
    this.active += 1;
    try {
      return { value: await fn() };
    } finally {
      this.active -= 1;
      const next = this.queue.shift();
      if (next) next();
    }
  }
}

module.exports = { TtlCache, Limiter };
