import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 产物路径固定为 frontend/dist，供 gui.go 的 //go:embed all:frontend/dist 使用。
// 不要改成相对路径（../frontend/dist），否则 go:embed 找不到目录。
export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2015',
    chunkSizeWarningLimit: 2048
  },
  server: {
    port: 5173,
    strictPort: false
  }
})