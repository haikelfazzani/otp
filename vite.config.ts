import { resolve } from "path";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: [
        resolve(__dirname, "src/index.ts"),
      ],
      name: "OTP",
      formats: ["es", "cjs", "umd"],
      fileName: (format) => `index.${format}.js`,
    }
  },
});