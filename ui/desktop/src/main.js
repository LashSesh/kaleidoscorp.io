import { mount } from "./bootstrap.js";
import { tauriSource } from "./transports/tauri.js";

const app = mount(document, tauriSource(globalThis.__TAURI__?.core?.invoke));
window.addEventListener("pagehide", () => app.dispose(), { once: true });
