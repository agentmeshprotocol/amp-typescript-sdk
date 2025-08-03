import { defineConfig } from 'vitest/config'
import { resolve } from 'path'

export default defineConfig({
  test: {
    globals: true,
    environment: 'happy-dom',
    setupFiles: ['./tests/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}', 'tests/**/*.{test,spec}.{ts,tsx}'],
    exclude: [
      'node_modules',
      'dist',
      'build',
      'tests/integration/**/*',
      'tests/e2e/**/*'
    ],
    
    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules',
        'dist',
        'build',
        'tests',
        'src/**/*.d.ts',
        'src/**/*.test.ts',
        'src/**/*.spec.ts',
        'src/**/index.ts',
        'vite.config.ts',
        'vitest.config.ts',
        'vitest.integration.config.ts'
      ],
      thresholds: {
        global: {
          branches: 80,
          functions: 80,
          lines: 80,
          statements: 80
        }
      }
    },
    
    // Test timeout
    testTimeout: 10000,
    hookTimeout: 10000,
    
    // Reporter
    reporter: ['verbose', 'json', 'html'],
    outputFile: {
      json: './coverage/test-results.json',
      html: './coverage/test-results.html'
    },
    
    // Retry configuration
    retry: 2,
    
    // Pool options
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: false
      }
    },
    
    // Watch options
    watch: {
      exclude: ['node_modules', 'dist', 'build', 'coverage']
    }
  },
  
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@/types': resolve(__dirname, 'src/types'),
      '@/utils': resolve(__dirname, 'src/utils'),
      '@/client': resolve(__dirname, 'src/client'),
      '@/transport': resolve(__dirname, 'src/transport'),
      '@/validation': resolve(__dirname, 'src/validation'),
      '@/frameworks': resolve(__dirname, 'src/frameworks')
    }
  },
  
  define: {
    __VERSION__: JSON.stringify(process.env.npm_package_version || '0.1.0'),
    __BUILD_DATE__: JSON.stringify(new Date().toISOString()),
    __DEV__: JSON.stringify(true)
  }
})