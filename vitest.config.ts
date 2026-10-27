import path from 'path';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
    dedupe: ['react', 'react-dom'],
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    include: ['src/components/**/*.test.tsx'],
    exclude: [
      '**/node_modules/**',
      '**/dist/**',
      'src/components/__tests__/DataFlowGraphView.test.tsx',
      'src/components/__tests__/IastTaintFlowVisualizer.test.tsx',
      'src/components/__tests__/SecurityRiskHeatmapCard.test.tsx',
      'src/components/__tests__/VulnerabilityTrendChart.test.tsx',
    ],
    testTimeout: 30000,
    hookTimeout: 20000,
    isolate: false,
    fileParallelism: false,
    maxWorkers: 1,
  },
});
