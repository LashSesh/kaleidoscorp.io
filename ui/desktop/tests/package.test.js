import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, posix, win32 } from "node:path";
import { packageUi, assets, outputContainsSource } from "../tools/package.mjs";

test("production package includes its module closure and excludes sample/server assets", async t => {
  const output = await mkdtemp(join(tmpdir(), "ssk desktop bundle "));
  t.after(() => rm(output, { recursive: true, force: true }));
  assert.deepEqual(await packageUi(output), [...assets]);
  assert.ok(assets.every(name => !/preview|fixture|test|tools/.test(name)));
  const html = await readFile(join(output, "index.html"), "utf8");
  assert.doesNotMatch(html, /http-equiv="Content-Security-Policy"/); // host injects compiled policy
  assert.match(html, /src="src\/main.js"/);
  for (const name of assets.filter(name => name.endsWith(".js"))) {
    const source = await readFile(join(output, name), "utf8");
    for (const [, specifier] of source.matchAll(/from\s*["']([^"']+)["']/g)) {
      assert.ok(assets.includes(posix.join(posix.dirname(name), specifier)), `${name}: missing ${specifier}`);
    }
  }
  await writeFile(join(output, "preview.html"), "old sample page");
  await assert.rejects(packageUi(output), /Unexpected output file/);
});

test("native capability grants only the bundled window's read command", async () => {
  const root = new URL("../../apps/desktop/", new URL("../", import.meta.url));
  const capability = JSON.parse(await readFile(new URL("capabilities/read-panel.json", root), "utf8"));
  assert.equal(capability.local, true);
  assert.deepEqual(capability.windows, ["main"]);
  assert.deepEqual(capability.permissions, ["allow-get-panel-snapshot-v2"]);
  assert.equal(capability.remote, undefined);
  const config = JSON.parse(await readFile(new URL("tauri.conf.json", root), "utf8"));
  assert.deepEqual(config.app.security.capabilities, ["read-panel"]);
  assert.doesNotMatch(config.app.security.csp, /unsafe-inline|unsafe-eval|https:|\*/);
  const build = await readFile(new URL("build.rs", root), "utf8");
  assert.match(build, /\.commands\(&\["get_panel_snapshot_v2"\]\)/);
});

// Regression: on the Windows CI runner the checkout is on D:\ while os.tmpdir() is on C:\.
// path.relative() then returns an ABSOLUTE path, which the old `!startsWith("..")` check
// read as "output contains the source" and rejected an unrelated output directory.
test("output guard: win32 cross-drive output is unrelated, not 'containing'", () => {
  const source = "D:\\a\\kaleidoscorp.io\\ui\\desktop\\";
  assert.equal(outputContainsSource("C:\\Users\\runner\\AppData\\Local\\Temp\\bundle", source, win32), false);
  assert.equal(outputContainsSource("D:\\a\\kaleidoscorp.io\\ui\\desktop\\dist", source, win32), false);
  assert.equal(outputContainsSource("D:\\a\\kaleidoscorp.io\\ui\\desktop", source, win32), true);
  assert.equal(outputContainsSource("D:\\a\\kaleidoscorp.io", source, win32), true);
  assert.equal(outputContainsSource("d:\\A\\KALEIDOSCORP.IO\\UI\\DESKTOP", source, win32), true, "win32 paths are case-insensitive");
});

test("output guard: posix equal, ancestor and descendant outputs", () => {
  const source = "/work/repo/ui/desktop/";
  assert.equal(outputContainsSource("/work/repo/ui/desktop", source, posix), true);
  assert.equal(outputContainsSource("/work/repo", source, posix), true);
  assert.equal(outputContainsSource("/", source, posix), true);
  assert.equal(outputContainsSource("/work/repo/ui/desktop/dist", source, posix), false);
  assert.equal(outputContainsSource("/tmp/bundle", source, posix), false);
  // A source directory literally named "..foo" is a child of its parent, not an escape.
  assert.equal(outputContainsSource("/work/repo/ui", "/work/repo/ui/..foo", posix), true);
});
