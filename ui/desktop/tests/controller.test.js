import test from "node:test";
import assert from "node:assert/strict";
import { createController } from "../src/controller.js";

const sample = state => ({ schema_version: 1, panel_state: state });
function setup(readSnapshot, kind = "desktop") {
  let id = 0;
  const jobs = new Map();
  const clock = {
    set(fn, delay) { jobs.set(++id, { fn, delay }); return id; },
    clear(key) { jobs.delete(key); },
    fire(delay) {
      for (const [key, job] of [...jobs]) if (job.delay === delay) { jobs.delete(key); job.fn(); }
    },
  };
  const views = [];
  const controller = createController({ source: { kind, readSnapshot },
    render: v => views.push(v), clock, timeoutMs: 10, freshnessMs: 20 });
  return { controller, views, clock, jobs };
}

test("disconnect has no backend calls; failures erase prior observations", async () => {
  const offline = setup(() => { throw new Error("must not run"); }, "disconnected");
  await offline.controller.refresh();
  assert.equal(offline.views.at(-1).phase, "disconnected");
  let fail = false;
  const x = setup(async () => { if (fail) throw new Error("offline"); return sample("engaged"); });
  await x.controller.refresh();
  assert.equal(x.views.at(-1).snapshot.panel_state, "engaged");
  fail = true;
  const update = x.controller.refresh();
  assert.equal(x.views.at(-1).snapshot, null);
  await update;
  assert.equal(x.views.at(-1).phase, "degraded");
  assert.equal(x.views.at(-1).snapshot, null);
  assert.equal(x.jobs.size, 0);
});

test("freshness expiry removes data; a new refresh can recover", async () => {
  const x = setup(async () => sample("ready"));
  await x.controller.refresh();
  x.clock.fire(20);
  assert.equal(x.views.at(-1).phase, "stale");
  assert.equal(x.views.at(-1).snapshot, null);
  await x.controller.refresh();
  assert.equal(x.views.at(-1).phase, "ready");
  x.controller.dispose();
  assert.equal(x.jobs.size, 0);
});

test("hung transport times out and late completion cannot restore data", async () => {
  let resolve;
  const x = setup(() => new Promise(done => { resolve = done; }));
  const pending = x.controller.refresh();
  await Promise.resolve();
  x.clock.fire(10);
  await pending;
  assert.equal(x.views.at(-1).phase, "degraded");
  resolve(sample("engaged"));
  await Promise.resolve();
  assert.equal(x.views.at(-1).snapshot, null);
});

test("only the latest request may update the view", async () => {
  const resolves = [];
  const x = setup(() => new Promise(done => resolves.push(done)));
  const first = x.controller.refresh();
  await Promise.resolve();
  const second = x.controller.refresh();
  await Promise.resolve();
  resolves[1](sample("released"));
  await second;
  resolves[0](sample("engaged"));
  await first;
  assert.equal(x.views.at(-1).snapshot.panel_state, "released");
  x.controller.dispose();
});

test("dispose aborts pending reads and prevents future rendering", async () => {
  const x = setup(() => new Promise(() => {}));
  const pending = x.controller.refresh();
  const count = x.views.length;
  x.controller.dispose();
  await pending;
  await x.controller.refresh();
  x.clock.fire(20);
  assert.equal(x.views.length, count);
  assert.equal(x.jobs.size, 0);
});

test("unsupported contract produces degraded instead of a partial observation", async () => {
  const x = setup(async () => ({ ...sample("engaged"), schema_version: 99 }));
  await x.controller.refresh();
  assert.equal(x.views.at(-1).phase, "degraded");
  assert.equal(x.views.at(-1).snapshot, null);
});
