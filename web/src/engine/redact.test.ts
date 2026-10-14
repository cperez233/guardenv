import { describe, expect, it } from "vitest";

import { SAMPLE_DOCUMENTS } from "@/lib/samples";
import { REDACTION_CHAR, redactDocument } from "./redact";
import { scanText } from "./scanner";

describe("redactDocument", () => {
  it("blacks out every finding in every sample and leaves nothing to report", () => {
    for (const sample of SAMPLE_DOCUMENTS) {
      const before = scanText(sample.content, { path: sample.filename });
      const { text, count } = redactDocument(sample.content, before.findings);
      for (const finding of before.findings) {
        expect(text).not.toContain(finding.match);
      }
      expect(count).toBeGreaterThanOrEqual(before.findings.length > 0 ? 1 : 0);
      const after = scanText(text, { path: sample.filename });
      expect(after.totalFindings).toBe(0);
    }
  });

  it("preserves line count and line lengths", () => {
    const sample = SAMPLE_DOCUMENTS[0] as (typeof SAMPLE_DOCUMENTS)[number];
    const before = scanText(sample.content, { path: sample.filename });
    const { text } = redactDocument(sample.content, before.findings);
    const a = sample.content.split("\n");
    const b = text.split("\n");
    expect(b).toHaveLength(a.length);
    b.forEach((line, i) => { expect(line.length).toBe((a[i] ?? "").length); });
    expect(text).toContain(REDACTION_CHAR);
  });

  it("is a no-op without findings", () => {
    expect(redactDocument("A=1", [])).toEqual({ text: "A=1", count: 0 });
  });
});
