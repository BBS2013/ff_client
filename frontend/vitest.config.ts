import { defineConfig } from 'vitest/config'

// 只测纯函数/纯状态模块：不引浏览器、不引 DOM。
// 覆盖闸门盯的也是这几份——界面组件的真实交互仍由人工点验（README §9 的边界）。
export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['src/format.ts', 'src/ageclock.ts', 'src/nodetests.ts', 'src/probes.ts'],
      reporter: ['text'],
      thresholds: {
        lines: 80,
        functions: 80,
        statements: 80,
        branches: 70
      }
    }
  }
})
