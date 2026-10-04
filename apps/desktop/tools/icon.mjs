// Reproducible temporary development icon; no external artwork or image tools.
import { mkdir, writeFile } from "node:fs/promises";
const size = 32;
const pixels = size * size * 4;
const mask = size * 4;
const bytes = Buffer.alloc(22 + 40 + pixels + mask);
bytes.writeUInt16LE(1, 2); bytes.writeUInt16LE(1, 4);
bytes[6] = size; bytes[7] = size;
bytes.writeUInt16LE(1, 10); bytes.writeUInt16LE(32, 12);
bytes.writeUInt32LE(40 + pixels + mask, 14); bytes.writeUInt32LE(22, 18);
bytes.writeUInt32LE(40, 22); bytes.writeInt32LE(size, 26); bytes.writeInt32LE(size * 2, 30);
bytes.writeUInt16LE(1, 34); bytes.writeUInt16LE(32, 36); bytes.writeUInt32LE(pixels, 42);
for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
  const mark = (x >= 8 && x <= 23 && ((y >= 6 && y <= 9) || (y >= 14 && y <= 17) || (y >= 22 && y <= 25))) ||
    (x >= 8 && x <= 11 && y >= 9 && y <= 14) || (x >= 20 && x <= 23 && y >= 17 && y <= 22);
  bytes.set(mark ? [230, 220, 210, 255] : [70, 35, 20, 255], 62 + ((size - y - 1) * size + x) * 4);
}
await mkdir(new URL("../icons/", import.meta.url), { recursive: true });
await writeFile(new URL("../icons/icon.ico", import.meta.url), bytes);
