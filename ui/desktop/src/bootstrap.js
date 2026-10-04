import { createController } from "./controller.js";
import { renderPanel } from "./components/panel.js";

export function mount(root, source) {
  const controller = createController({ source, render: model => renderPanel(root, model) });
  const refresh = root.querySelector("#refresh");
  const onRefresh = () => { void controller.refresh(); };
  refresh.addEventListener("click", onRefresh);
  void controller.refresh();
  return {
    refresh: controller.refresh,
    dispose() { refresh.removeEventListener("click", onRefresh); controller.dispose(); },
  };
}
