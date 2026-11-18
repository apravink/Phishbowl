import { defineConfig } from "vite";
import { resolve } from "node:path"

export default defineConfig({
  build: {
    outDir:"dist",
    rolldownOptions: {
        input: {
            background: resolve(__dirname, "src/background/index.ts"),
        },
        output: { entryFileNames: "[name].js"}
    }
  }
});