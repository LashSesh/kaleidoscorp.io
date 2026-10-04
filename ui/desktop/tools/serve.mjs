// Static development preview only: loopback, no backend or command endpoints.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve, sep, extname } from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8" };
export function createPreviewServer() {
return createServer(async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
  if (!["GET", "HEAD"].includes(req.method)) { res.writeHead(405).end(); return; }
  try {
    const requested = decodeURIComponent(new URL(req.url, "http://127.0.0.1").pathname);
    const pathname = requested === "/" ? "/index.html" : requested;
    const target = resolve(root, "." + pathname);
    if (!target.startsWith(resolve(root) + sep) || !types[extname(target)] ||
        pathname.includes("\\") || pathname.includes("\0") ||
        !/^\/(index\.html|preview\.html|styles\.css|src\/|fixtures\/)/.test(pathname)) {
      res.writeHead(404).end(); return;
    }
    const bytes = await readFile(target);
    res.setHeader("Content-Type", types[extname(target)]);
    res.writeHead(200).end(req.method === "HEAD" ? undefined : bytes);
  } catch { res.writeHead(404).end(); }
});
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
const port = Number(process.env.SSK_UI_PORT ?? 5173);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error("Invalid SSK_UI_PORT");
const server = createPreviewServer();
server.listen(port, "127.0.0.1", () => {
  console.log(`Desktop shell: http://127.0.0.1:${port}/\nUI preview: http://127.0.0.1:${port}/preview.html`);
});
}
