/**
 * The finding's description in the interface language. Exports keep the
 * engine's English text; this only changes what the inspector shows.
 */
import type { ScanFinding } from "@/engine/types";

import type { Lang } from "./context";
import { RULE_DESCRIPTIONS_ES } from "./rules.es";

const ENCODED = /^Base64-encoded value that decodes to (\S+)\. /;
const ENTROPY = /^(\w+) string with ([\d.]+) bits\/char of entropy \(threshold ([\d.]+)\)\.$/;

export function describeFinding(finding: ScanFinding, lang: Lang): string {
  if (lang === "en") return finding.description;
  const encoded = ENCODED.exec(finding.description);
  if (encoded !== null) {
    const inner = RULE_DESCRIPTIONS_ES[finding.ruleId] ?? finding.description.slice(encoded[0].length);
    return `Valor en base64 que se decodifica como ${encoded[1] ?? ""}. ${inner}`;
  }
  const entropy = ENTROPY.exec(finding.description);
  if (entropy !== null) {
    return `Cadena ${entropy[1] ?? ""} con ${entropy[2] ?? ""} bits/carácter de entropía (umbral ${entropy[3] ?? ""}).`;
  }
  return RULE_DESCRIPTIONS_ES[finding.ruleId] ?? finding.description;
}
