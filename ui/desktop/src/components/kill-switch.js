import { text } from "./dom.js";
import { protectionView } from "../presentation.js";

export function renderKillSwitch(root, model) {
  const view = protectionView(model);
  const light = root.querySelector("#ks-light");
  light.className = "light " + view.tone;
  text(root.querySelector("#ks-headline"), view.text);
  const fields = root.querySelector("#ks-fields");
  fields.replaceChildren();
  const k = model.snapshot?.kill_switch;
  if (!k) return;
  for (const [label, value] of [
    ["Logischer Zustand", k.logical_state], ["Betriebssystemregel", k.os_rule],
    ["Abgleich", k.recovery], ["Bestätigung gemeldet", k.protection_confirmed],
    ["Zustandsversion", k.state_version],
  ]) {
    const dt = fields.ownerDocument.createElement("dt");
    const dd = fields.ownerDocument.createElement("dd");
    text(dt, label); text(dd, value);
    fields.append(dt, dd);
  }
}
