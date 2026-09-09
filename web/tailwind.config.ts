import type { Config } from "tailwindcss";

/**
 * Palette notes: the surface ramp is intentionally close to Vercel/Linear -
 * near-black grounds with hairline borders, so that the severity accents
 * (crimson for critical, emerald for clean) are the only saturated colour on
 * screen and therefore carry all the signal.
 */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          0: "#09090b",
          1: "#0c0c0f",
          2: "#111114",
          3: "#18181b",
          4: "#1f1f23",
        },
        hairline: {
          DEFAULT: "#27272a",
          strong: "#3f3f46",
        },
        content: {
          primary: "#fafafa",
          secondary: "#a1a1aa",
          tertiary: "#71717a",
          faint: "#52525b",
        },
        severity: {
          critical: "#f43f5e",
          high: "#fb7185",
          medium: "#f59e0b",
          low: "#38bdf8",
          info: "#a1a1aa",
          clean: "#10b981",
        },
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "Liberation Mono",
          "monospace",
        ],
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0", transform: "translateY(4px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        "pulse-ring": {
          "0%": { boxShadow: "0 0 0 0 rgb(16 185 129 / 0.45)" },
          "70%": { boxShadow: "0 0 0 6px rgb(16 185 129 / 0)" },
          "100%": { boxShadow: "0 0 0 0 rgb(16 185 129 / 0)" },
        },
      },
      animation: {
        "fade-in": "fade-in 160ms ease-out",
        "pulse-ring": "pulse-ring 2s ease-out infinite",
      },
    },
  },
  plugins: [],
} satisfies Config;
