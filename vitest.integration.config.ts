import { defineConfig } from 'vitest/config'
import { resolve } from 'path'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    setupFiles: ['./tests/integration/setup.ts'],
    include: ['tests/integration/**/*.{test,spec}.{ts,tsx}'],
    exclude: [
      'node_modules',
      'dist',
      'build',
      'src/**/*.test.ts',
      'tests/unit/**/*',
      'tests/e2e/**/*'
    ],
    
    // Integration tests typically need more time
    testTimeout: 30000,
    hookTimeout: 30000,
    
    // Reporter
    reporter: ['verbose'],
    
    // Retry configuration for potentially flaky network tests
    retry: 3,
    
    // Run integration tests sequentially to avoid conflicts
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true
      }
    },
    
    // Environment variables for integration tests
    env: {
      NODE_ENV: 'test',
      AMP_TEST_MODE: 'integration'
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