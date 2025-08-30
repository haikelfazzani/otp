import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import path from 'node:path';

export default defineConfig({
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/index.ts'),
      name: 'otp',
      fileName: (format) => format === 'es' ? 'index.js' : `index.${format}.js`,
      formats: ['es', 'umd'],
    },
    sourcemap: false,
  },
  plugins: [
    dts({
      insertTypesEntry: true,
      outDir: "dist/types",
      copyDtsFiles: true,
      // rollupTypes:true
    }),
  ]
});
