import type { Config } from "tailwindcss";

/**
 * Palette notes: the playground is dressed as an audit file. A cool, steel-grey
 * sheet (not cream) carries graphite ink; the only non-semantic colour is the
 * auditor's highlighter, used as a mark *behind* text, never as text. Every
 * token is a CSS variable (src/index.css) so the dark theme is a second set of
 * values, not a second set of classes.
 */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["selector", '[data-theme="dark"]'],
  // Hover styles only where a real pointer hovers; touch gets :active instead.
  future: { hoverOnlyWhenSupported: true },
  theme: {
    extend: {
      colors: {
        surface: {
          0: "rgb(var(--c-surface-0) / <alpha-value>)",
          1: "rgb(var(--c-surface-1) / <alpha-value>)",
          2: "rgb(var(--c-surface-2) / <alpha-value>)",
          3: "rgb(var(--c-surface-3) / <alpha-value>)",
          4: "rgb(var(--c-surface-4) / <alpha-value>)",
        },
        hairline: {
          DEFAULT: "rgb(var(--c-hairline) / <alpha-value>)",
          strong: "rgb(var(--c-hairline-strong) / <alpha-value>)",
        },
        content: {
          primary: "rgb(var(--c-content-primary) / <alpha-value>)",
          secondary: "rgb(var(--c-content-secondary) / <alpha-value>)",
          tertiary: "rgb(var(--c-content-tertiary) / <alpha-value>)",
          faint: "rgb(var(--c-content-faint) / <alpha-value>)",
        },
        // "Ink" is the redaction bar and the primary action. It inverts with the
        // theme: graphite on the light sheet, paper-white on the dark one.
        ink: {
          DEFAULT: "rgb(var(--c-ink) / <alpha-value>)",
          soft: "rgb(var(--c-ink-soft) / <alpha-value>)",
          accent: "rgb(var(--c-ink-accent) / <alpha-value>)",
        },
        mark: {
          DEFAULT: "#e3f24a",
          soft: "#eef7a3",
          deep: "#b9c92a",
        },
        // Text set on the highlighter: always dark, whatever the theme.
        "on-mark": "#101317",
        severity: {
          critical: "rgb(var(--c-sev-critical) / <alpha-value>)",
          high: "rgb(var(--c-sev-high) / <alpha-value>)",
          medium: "rgb(var(--c-sev-medium) / <alpha-value>)",
          low: "rgb(var(--c-sev-low) / <alpha-value>)",
          info: "rgb(var(--c-sev-info) / <alpha-value>)",
          clean: "rgb(var(--c-sev-clean) / <alpha-value>)",
        },
      },
      fontFamily: {
        sans: ["'Public Sans'", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        display: ["Archivo", "'Public Sans'", "ui-sans-serif", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        // One elevation scale, tinted to the graphite ink.
        rest: "0 1px 0 rgb(var(--c-shadow) / 0.04), 0 1px 2px rgb(var(--c-shadow) / 0.06)",
        raised: "0 1px 0 rgb(var(--c-shadow) / 0.04), 0 12px 32px -12px rgb(var(--c-shadow) / var(--shadow-strength, 0.18))",
        float: "0 1px 0 rgb(var(--c-shadow) / 0.05), 0 24px 60px -20px rgb(var(--c-shadow) / var(--shadow-float, 0.32))",
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
