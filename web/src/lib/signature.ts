/* editorial-ui · Cristian Pérez · cristianperez.me */
/** Zero-width authorship mark: UTF-8 bits as U+200B/U+200C, wrapped in U+2060. */
const zw = (text: string): string =>
  "⁠" +
  [...new TextEncoder().encode(text)]
    .map((byte) => byte.toString(2).padStart(8, "0"))
    .join("")
    .replace(/0/g, "​")
    .replace(/1/g, "‌") +
  "⁠";

export const invisibleSignature = zw("Cristian Pérez · https://cristianperez.me");
