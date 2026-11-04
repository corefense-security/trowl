import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";

// One self-contained HTML file; the Python side injects report JSON into it.
export default defineConfig({
  plugins: [react(), viteSingleFile()],
  build: {
    outDir: "../internal/report/ui",
    emptyOutDir: false, // keeps ui/.gitkeep so the Go embed works before the first UI build
  },
});
