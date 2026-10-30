/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url'

import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    rolldownOptions: {
      output: {
        // Long-lived vendor chunks: app deploys do not invalidate them.
        codeSplitting: {
          groups: [
            {
              name: 'react',
              test: /node_modules[\\/](react|react-dom|scheduler|react-router|use-sync-external-store)[\\/]/,
            },
            { name: 'radix', test: /node_modules[\\/](@radix-ui|radix-ui)[\\/]/ },
            // Graph-only libraries stay with the lazily loaded graph tab.
            {
              name: 'graph-vendor',
              test: /node_modules[\\/](@xyflow|@dagrejs|d3-[a-z-]+|classcat|zustand)[\\/]/,
            },
            { name: 'vendor', test: /node_modules[\\/]/ },
          ],
        },
      },
    },
  },
  server: {
    proxy: {
      // app/scripts/dev sets this from API_PORT.
      '/api': process.env.VITE_API_PROXY ?? 'http://127.0.0.1:8000',
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
})
