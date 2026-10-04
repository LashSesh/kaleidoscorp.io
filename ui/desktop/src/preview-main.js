import { mount } from "./bootstrap.js";
import { previewSource } from "./transports/preview.js";

const selector = document.querySelector("#scenario");
const app = mount(document, previewSource(() => selector.value));
selector.addEventListener("change", () => { void app.refresh(); });
window.addEventListener("pagehide", () => app.dispose(), { once: true });
