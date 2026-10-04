// Deterministic asset allow-list: no preview entry, fixtures, tests or server.
import { readFile, mkdir, writeFile, readdir, lstat } from "node:fs/promises";
import { resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const source = fileURLToPath(new URL("../", import.meta.url));
export const assets = Object.freeze([
  "index.html", "styles.css", "src/main.js", "src/bootstrap.js", "src/controller.js",
  "src/contract.js", "src/presentation.js", "src/transports/tauri.js",
  "src/components/dom.js", "src/components/panel.js", "src/components/kill-switch.js",
  "src/components/audit.js", "src/components/connections.js", "src/components/daemon.js",
]);

async function inventory(directory, prefix = "") {
  const found = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const name = prefix + entry.name;
    if (entry.isSymbolicLink()) throw new Error("Reparse/symlink in output");
    if (entry.isDirectory()) found.push(...await inventory(resolve(directory, entry.name), name + "/"));
    else found.push(name);
  }
  return found;
}

export async function packageUi(destination) {
  const output = resolve(destination);
  if (output === resolve(source) || relative(output, source).startsWith("..") === false) {
    throw new Error("Output must not contain the UI source");
  }
  await mkdir(output, { recursive: true });
  if ((await lstat(output)).isSymbolicLink()) throw new Error("Symlink output");
  for (const name of await inventory(output)) if (!assets.includes(name)) {
    throw new Error("Unexpected output file; use a fresh output directory: " + name);
  }
  for (const name of assets) {
    let bytes = await readFile(resolve(source, name));
    if (name === "index.html") {
      // Tauri injects the configured CSP with its script hashes at compile time.
      const html = bytes.toString("utf8");
      const pattern = /  <meta http-equiv="Content-Security-Policy"[^>]*>\r?\n/;
      if (!pattern.test(html)) throw new Error("Expected browser CSP tag");
      bytes = Buffer.from(html.replace(pattern, ""));
    }
    const path = resolve(output, name);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes);
  }
  return [...assets];
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await packageUi(fileURLToPath(new URL("../dist/", import.meta.url)));
  console.log("Packaged production UI; preview assets excluded.");
}
