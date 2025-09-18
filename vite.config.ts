import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import path from 'node:path';

export default defineConfig({
  plugins: [
    dts({
      insertTypesEntry: true,
      tsconfigPath: './tsconfig.json',
      outDir: "dist/types",
      rollupTypes: true
    }),
  ],
  build: {
    lib: {
      entry: path.resolve(__dirname, 'index.ts'),
      name: 'otp',
      fileName: (format) => format === 'es' ? 'index.js' : `index.${format}.js`,
      formats: ['es', 'umd'],
    },
    sourcemap: false,
    rollupOptions: {
      external: ["node:crypto"],
    },
  }
});
