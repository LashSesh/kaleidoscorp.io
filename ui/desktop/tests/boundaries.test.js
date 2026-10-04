import test from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { resolve, relative, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../src/", import.meta.url));
async function files(dir) {
  const found = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) found.push(...await files(path));
    else if (path.endsWith(".js")) found.push(path);
  }
  return found;
}

test("UI dependency boundaries: components have no transport and production has no preview", async () => {
  const graph = new Map();
  for (const path of await files(root)) {
    const source = await readFile(path, "utf8");
    const imports = [...source.matchAll(/(?:from\s*|import\s*)["']([^"']+)["']/g)].map(m => m[1]);
    assert.doesNotMatch(source, /\bimport\s*\(|\brequire\s*\(/, "dynamic imports require architecture review");
    const targets = imports.map(specifier => {
      assert.ok(specifier.startsWith("."), "UI must not depend on host/npm modules");
      const target = resolve(dirname(path), specifier);
      assert.ok(!relative(root, target).startsWith(".."), "source import escaped the UI");
      return target;
    });
    graph.set(path, targets);
    const name = relative(root, path).replaceAll("\\", "/");
    if (name.startsWith("components/") || ["contract.js", "presentation.js", "controller.js"].includes(name)) {
      assert.ok(targets.every(t => !relative(root, t).replaceAll("\\", "/").startsWith("transports/")));
      assert.doesNotMatch(source, /\bfetch\s*\(|__TAURI__|\binvoke\s*\(/);
    }
  }
  const seen = new Set();
  const visit = path => { if (seen.has(path)) return; seen.add(path); for (const dep of graph.get(path) ?? []) visit(dep); };
  visit(resolve(root, "main.js"));
  assert.ok([...seen].every(p => !relative(root, p).includes("preview")));
  for (const entry of ["index.html", "preview.html"]) {
    const html = await readFile(new URL("../" + entry, import.meta.url), "utf8");
    assert.match(html, /type="module"/);
    assert.doesNotMatch(html, /https?:\/\//);
  }
});
