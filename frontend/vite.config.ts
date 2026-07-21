import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

// https://vitejs.dev/config
export default defineConfig({
    server: {
    // 1. Array of allowed custom domains
    allowedHosts: ['x-reg.duckdns.org']
  },
  build: {
    outDir: '../static',
    emptyOutDir: true
  },
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
})
