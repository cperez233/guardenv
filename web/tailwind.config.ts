import type { Config } from "tailwindcss";

/**
 * Palette notes: the playground is dressed as an audit file. A cool, steel-grey
 * sheet (not cream) carries graphite ink; the only non-semantic colour is the
 * auditor's highlighter, used as a mark *behind* text, never as text. Severity
 * hues are deepened so they read on paper rather than glow on black.
 */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  // Hover styles only where a real pointer hovers; touch gets :active instead.
  future: { hoverOnlyWhenSupported: true },
  theme: {
    extend: {
      colors: {
        surface: {
          0: "#e6e8eb",
          1: "#f4f5f7",
          2: "#eceef1",
          3: "#e1e4e8",
          4: "#d5d9de",
        },
        hairline: {
          DEFAULT: "#cfd4da",
          strong: "#a7aeb7",
        },
        content: {
          primary: "#101317",
          secondary: "#363d46",
          tertiary: "#565e68",
          faint: "#737b85",
        },
        ink: {
          DEFAULT: "#101317",
          soft: "#1c2128",
        },
        mark: {
          DEFAULT: "#e3f24a",
          soft: "#eef7a3",
          deep: "#b9c92a",
        },
        severity: {
          critical: "#c42033",
          high: "#cf4a17",
          medium: "#9a6400",
          low: "#1d68ad",
          info: "#5e6670",
          clean: "#17774a",
        },
      },
      fontFamily: {
        sans: ["'Public Sans'", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        display: ["Archivo", "'Public Sans'", "ui-sans-serif", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        // One elevation scale, tinted to the graphite ink.
        rest: "0 1px 0 rgb(16 19 23 / 0.04), 0 1px 2px rgb(16 19 23 / 0.06)",
        raised: "0 1px 0 rgb(16 19 23 / 0.04), 0 12px 32px -12px rgb(16 19 23 / 0.18)",
        float: "0 1px 0 rgb(16 19 23 / 0.05), 0 24px 60px -20px rgb(16 19 23 / 0.32)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "fade-in": "fade-in 160ms ease-out",
      },
    },
  },
  plugins: [],
} satisfies Config;
