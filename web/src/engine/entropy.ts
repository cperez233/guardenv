/**
 * Shannon entropy analysis - a faithful TypeScript port of `guardenv/entropy.py`.
 *
 * The playground runs entirely offline, so this file must reproduce the Python
 * detector's verdicts exactly; `entropy.test.ts` pins the shared expectations.
 */

import type { CharsetKind, EntropyResult } from "./types";

export interface EntropyConfig {
  readonly minLength: number;
  readonly maxLength: number;
  readonly hexThreshold: number;
  readonly base64Threshold: number;
  readonly genericThreshold: number;
  readonly minUniqueRatio: number;
  readonly useHeuristics: boolean;
}

export const DEFAULT_ENTROPY_CONFIG: EntropyConfig = {
  minLength: 20,
  maxLength: 512,
  hexThreshold: 3.0,
  base64Threshold: 4.5,
  genericThreshold: 4.0,
  minUniqueRatio: 0.3,
  useHeuristics: true,
};

/**
 * Build a config where every charset shares one absolute threshold.
 * This is what the UI slider drives.
 */
export function configWithThreshold(threshold: number, useHeuristics = true): EntropyConfig {
  return {
    ...DEFAULT_ENTROPY_CONFIG,
    hexThreshold: threshold,
    base64Threshold: threshold,
    genericThreshold: threshold,
    useHeuristics,
  };
}

const LOG2 = Math.LOG2E;

/** Memoize the kernel: pasted files repeat the same tokens across many lines. */
const entropyCache = new Map<string, number>();
const ENTROPY_CACHE_LIMIT = 4096;

function computeEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  const length = value.length;
  let total = 0;
  for (const count of counts.values()) {
    const p = count / length;
    total -= p * Math.log(p) * LOG2;
  }
  return total;
}

/** Shannon entropy of `value`, in bits per character. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  if (value.length > 1024) return computeEntropy(value);

  const cached = entropyCache.get(value);
  if (cached !== undefined) return cached;

  const result = computeEntropy(value);
  if (entropyCache.size >= ENTROPY_CACHE_LIMIT) entropyCache.clear();
  entropyCache.set(value, result);
  return result;
}

/**
 * Entropy scaled to [0, 1] against the token's own alphabet size, so tokens
 * drawn from different alphabets can be compared on one axis.
 */
export function normalizedEntropy(value: string): number {
  if (value.length < 2) return 0;
  const alphabet = new Set(value).size;
  if (alphabet < 2) return 0;
  const ceiling = Math.log2(Math.min(alphabet, value.length));
  if (ceiling <= 0) return 0;
  return Math.min(1, shannonEntropy(value) / ceiling);
}

const HEX_RE = /^[0-9a-fA-F]+$/;
const ALNUM_RE = /^[A-Za-z0-9]+$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+={0,2}$/;

export function classifyCharset(token: string): CharsetKind {
  if (HEX_RE.test(token)) return "hex";
  if (ALNUM_RE.test(token)) return "alphanumeric";
  if (BASE64_RE.test(token)) return "base64";
  if (BASE64URL_RE.test(token)) return "base64url";
  return "mixed";
}

export function thresholdFor(charset: CharsetKind, config: EntropyConfig): number {
  if (charset === "hex") return config.hexThreshold;
  if (charset === "base64" || charset === "base64url") return config.base64Threshold;
  return config.genericThreshold;
}

// --------------------------------------------------------------------------
// Benign-shape heuristics
// --------------------------------------------------------------------------

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z?)?$/;
const SEMVER_RE = /^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$/;
const PATH_RE = /^(?:[./~]|[A-Za-z]:\\)|[/\\]{2,}/;
const NUMERIC_RE = /^[0-9._,-]+$/;
const CSS_COLOR_RE = /^#[0-9a-fA-F]{3,8}$/;
const WORDY_RE = /^[A-Za-z]+(?:[_-][A-Za-z]+)+$/;
const DOTTED_RE = /^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+\.?$/;
/** Splits a dotted/underscored/slashed identifier into its word segments. */
const SEGMENT_SPLIT_RE = /[._\-/]+/;
const MIME_DATA_RE = /^data:[a-z]+\//i;
const INTEGRITY_RE = /^sha(?:256|384|512)-/i;

/** Substrings that mark a token as documentation, a template or a stub. */
export const PLACEHOLDER_MARKERS: readonly string[] = [
  "changeme",
  "your_",
  "yourapi",
  "yourkey",
  "example",
  "placeholder",
  "dummy",
  "sample",
  "insert",
  "replace",
  "todo",
  "fixme",
  "xxxxxx",
  "000000",
  "111111",
  "abcdef0123",
  "notarealkey",
  "fake",
  "test_key",
  "dummykey",
  "lorem",
  "foobar",
  "<your",
  "${",
  "{{",
  "%s",
];

function looksLikeEnglish(token: string): boolean {
  if (WORDY_RE.test(token)) return true;
  let humps = 0;
  for (let i = 1; i < token.length; i += 1) {
    const char = token[i];
    if (char !== undefined && char >= "A" && char <= "Z") humps += 1;
  }
  const first = token[0] ?? "";
  // camelCase with no digits is almost never a secret: real tokens in this
  // length range essentially always carry digits.
  return humps >= 2 && !/\d/.test(token) && first >= "a" && first <= "z";
}

/**
 * True when `token` contains a long ascending character run. Alphabet constants
 * (`0123456789abcdef...`) score maximum entropy while carrying no information.
 */
function hasSequentialRun(token: string, length = 8): boolean {
  let run = 1;
  for (let i = 1; i < token.length; i += 1) {
    run = token.charCodeAt(i) - token.charCodeAt(i - 1) === 1 ? run + 1 : 1;
    if (run >= length) return true;
  }
  return false;
}

function longestRun(token: string): number {
  let best = 1;
  let run = 1;
  for (let i = 1; i < token.length; i += 1) {
    run = token[i] === token[i - 1] ? run + 1 : 1;
    if (run > best) best = run;
  }
  return best;
}

export interface BenignVerdict {
  readonly benign: boolean;
  readonly reason: string;
}

/** Cheap structural checks that run before the entropy comparison. */
export function isBenignToken(
  token: string,
  config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
): BenignVerdict {
  if (!config.useHeuristics) return { benign: false, reason: "" };

  const lowered = token.toLowerCase();

  if (UUID_RE.test(token)) return { benign: true, reason: "uuid" };
  if (ISO_DATE_RE.test(token)) return { benign: true, reason: "iso-8601-timestamp" };
  if (SEMVER_RE.test(token)) return { benign: true, reason: "semantic-version" };
  if (NUMERIC_RE.test(token)) return { benign: true, reason: "numeric-literal" };
  if (CSS_COLOR_RE.test(token)) return { benign: true, reason: "css-color" };
  if (PATH_RE.test(token)) return { benign: true, reason: "filesystem-path" };
  if (MIME_DATA_RE.test(token)) return { benign: true, reason: "data-uri" };
  if (INTEGRITY_RE.test(token)) {
    return { benign: true, reason: "subresource-integrity-hash" };
  }
  if (PLACEHOLDER_MARKERS.some((marker) => lowered.includes(marker))) {
    return { benign: true, reason: "documentation-placeholder" };
  }
  if (looksLikeEnglish(token)) return { benign: true, reason: "word-like-identifier" };
  if (DOTTED_RE.test(token)) return { benign: true, reason: "hostname-or-dotted-identifier" };
  if (hasSequentialRun(token)) return { benign: true, reason: "sequential-character-run" };

  // A dotted/underscored/slashed identifier - `entropy_config.hex_threshold`,
  // `github/codeql-action/upload-sarif`. Long as a whole, but every segment is a
  // short word: no single part of it is long enough to be a credential.
  const segments = token.split(SEGMENT_SPLIT_RE);
  if (segments.length >= 2 && Math.max(...segments.map((s) => s.length)) < config.minLength) {
    return { benign: true, reason: "structured-identifier" };
  }

  const uniqueRatio = new Set(token).size / token.length;
  if (uniqueRatio < config.minUniqueRatio) {
    return { benign: true, reason: "low-character-variety" };
  }
  if (longestRun(token) >= Math.max(4, Math.floor(token.length / 3))) {
    return { benign: true, reason: "repeated-character-run" };
  }
  return { benign: false, reason: "" };
}

// --------------------------------------------------------------------------
// Token extraction
// --------------------------------------------------------------------------

/**
 * `=` is excluded from the interior class on purpose: it is the assignment
 * operator in every config format, so allowing it would fuse `API_KEY=<value>`
 * into one token and score the variable name as part of the secret. It is
 * re-admitted only as trailing base64 padding.
 */
const CANDIDATE_RE = /[A-Za-z0-9+/_\-.~]{16,}={0,2}/g;

export interface Candidate {
  readonly token: string;
  readonly offset: number;
}

function trimToken(raw: string): { token: string; shift: number } {
  let start = 0;
  let end = raw.length;
  const trimmable = "._-~";
  while (start < end && trimmable.includes(raw[start] ?? "")) start += 1;
  while (end > start && trimmable.includes(raw[end - 1] ?? "")) end -= 1;
  return { token: raw.slice(start, end), shift: start };
}

/** Yield the tokens in `text` that are worth scoring. */
export function extractCandidates(
  text: string,
  config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
): Candidate[] {
  const results: Candidate[] = [];
  CANDIDATE_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = CANDIDATE_RE.exec(text)) !== null) {
    const raw = match[0];
    const { token, shift } = trimToken(raw);
    if (token.length === 0) continue;
    const offset = match.index + shift;
    if (token.length >= config.minLength && token.length <= config.maxLength) {
      results.push({ token, offset });
    } else if (token.length > config.maxLength) {
      results.push({ token: token.slice(0, config.maxLength), offset });
    }
  }
  return results;
}

/** Score one token against the configured thresholds. */
export function analyzeToken(
  token: string,
  line: number,
  column: number,
  config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
): EntropyResult {
  const charset = classifyCharset(token);
  const threshold = thresholdFor(charset, config);
  const entropy = shannonEntropy(token);
  const normalized = normalizedEntropy(token);
  const base = { token, entropy, normalized, charset, threshold, line, column } as const;

  if (token.length < config.minLength) {
    return { ...base, suspicious: false, reason: "too-short" };
  }
  const verdict = isBenignToken(token, config);
  if (verdict.benign) {
    return { ...base, suspicious: false, reason: verdict.reason };
  }
  const suspicious = entropy >= threshold;
  return {
    ...base,
    suspicious,
    reason: suspicious ? "above-threshold" : "below-threshold",
  };
}

/**
 * Score every candidate in the document.
 *
 * Unlike the CLI this returns *all* results, not just the suspicious ones: the
 * playground's scatter plot needs the rejected tokens too, so the reader can
 * see where the threshold currently sits relative to real data.
 */
export function profileDocument(
  text: string,
  config: EntropyConfig = DEFAULT_ENTROPY_CONFIG,
): EntropyResult[] {
  const profile: EntropyResult[] = [];
  const lines = text.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (line.length > 20_000) continue;
    for (const candidate of extractCandidates(line, config)) {
      profile.push(analyzeToken(candidate.token, index + 1, candidate.offset + 1, config));
    }
  }
  return profile;
}
