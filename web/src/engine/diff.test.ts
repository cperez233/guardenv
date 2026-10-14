import { describe, expect, it } from "vitest";

import { SAMPLE_DOCUMENTS } from "@/lib/samples";
import { looksLikeDiff, mapDiffFindings, parseDiff } from "./diff";
import { scanText } from "./scanner";

const patch = SAMPLE_DOCUMENTS.find((doc) => doc.id === "diff")?.content ?? "";

describe("diff mode", () => {
  it("recognises unified diffs and nothing else", () => {
    expect(looksLikeDiff(patch)).toBe(true);
    for (const doc of SAMPLE_DOCUMENTS.filter((d) => d.id !== "diff")) {
      expect(looksLikeDiff(doc.content)).toBe(false);
    }
  });

  it("keeps line numbers and attributes each line to its file", () => {
    const diff = parseDiff(patch);
    expect(diff.stripped.split("\n")).toHaveLength(patch.split("\n").length);
    expect(diff.fileNames).toEqual(["config/settings.py", ".env.production"]);
  });

  it("flags removed secrets as removed and added ones as added, at the right column", () => {
    const diff = parseDiff(patch);
    const findings = mapDiffFindings(scanText(diff.stripped).findings, diff, "fix.diff");
    const lines = patch.split("\n");
    const removed = findings.filter((f) => f.tags.includes("diff-removed"));
    const added = findings.filter((f) => f.tags.includes("diff-added"));
    expect(removed.map((f) => f.ruleId)).toEqual(
      expect.arrayContaining(["stripe-secret-key", "postgres-connection-string"]),
    );
    expect(added.map((f) => f.ruleId)).toContain("aws-access-key-id");
    for (const finding of findings) {
      expect(lines[finding.line - 1]?.slice(finding.column - 1)).toContain(finding.match);
    }
    expect(added.every((f) => f.path === ".env.production")).toBe(true);
    expect(removed.every((f) => f.path === "config/settings.py")).toBe(true);
  });
});
