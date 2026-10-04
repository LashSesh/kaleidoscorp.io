import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createPreviewServer } from "../tools/serve.mjs";

test("preview server serves both entries, modules and fixtures but no repository or command API", async () => {
  const server = createPreviewServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const path of ["/", "/index.html", "/preview.html", "/src/main.js", "/fixtures/engaged.json"]) {
      const response = await fetch(base + path);
      assert.equal(response.status, 200, path);
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.match(response.headers.get("content-security-policy"), /frame-ancestors 'none'/);
      await response.arrayBuffer();
    }
    for (const path of ["/package.json", "/tests/contract.test.js", "/%2e%2e/Cargo.toml", "/.git/config", "/api/execute"]) {
      const response = await fetch(base + path);
      assert.equal(response.status, 404, path);
      await response.arrayBuffer();
    }
    const head = await fetch(base + "/", { method: "HEAD" });
    assert.equal(head.status, 200);
    assert.equal(await head.text(), "");
    const post = await fetch(base + "/", { method: "POST" });
    assert.equal(post.status, 405);
    await post.arrayBuffer();
  } finally {
    const closing = new Promise(resolve => server.close(resolve));
    server.closeAllConnections();
    await closing;
  }
});
