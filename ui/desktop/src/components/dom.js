export function text(element, value) { element.textContent = value == null ? "—" : String(value); }
export function rows(body, values) {
  body.replaceChildren();
  for (const cells of values) {
    const row = body.ownerDocument.createElement("tr");
    for (const value of cells) {
      const cell = body.ownerDocument.createElement("td");
      text(cell, value);
      row.append(cell);
    }
    body.append(row);
  }
}
