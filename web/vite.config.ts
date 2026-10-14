import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  // Absolute base: the app is served from the root of its own domain.
  base: "/",
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    target: "es2022",
    // Two entry pages: the same app, with English and Spanish share metadata,
    // because link previews are read from the HTML, not from the running app.
    rollupOptions: {
      input: {
        main: fileURLToPath(new URL("./index.html", import.meta.url)),
        es: fileURLToPath(new URL("./es/index.html", import.meta.url)),
      },
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
