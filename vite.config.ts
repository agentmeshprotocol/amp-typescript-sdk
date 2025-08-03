import { defineConfig } from 'vite'
import dts from 'vite-plugin-dts'
import { resolve } from 'path'

export default defineConfig({
  plugins: [
    dts({
      insertTypesEntry: true,
      include: ['src/**/*'],
      exclude: ['src/**/*.test.ts', 'src/**/*.spec.ts'],
      rollupTypes: true,
      copyDtsFiles: true
    })
  ],
  
  build: {
    lib: {
      entry: {
        index: resolve(__dirname, 'src/index.ts'),
        browser: resolve(__dirname, 'src/browser.ts'),
        node: resolve(__dirname, 'src/node.ts')
      },
      name: 'AMPSdk',
      formats: ['es', 'cjs', 'umd', 'iife'],
      fileName: (format, entryName) => {
        const formatMap = {
          es: 'mjs',
          cjs: 'js',
          umd: 'umd.js',
          iife: 'iife.js'
        }
        const ext = formatMap[format as keyof typeof formatMap] || 'js'
        return entryName === 'index' ? `index.${ext}` : `${entryName}.${ext}`
      }
    },
    
    rollupOptions: {
      external: [
        // Node.js built-ins
        'crypto',
        'events',
        'http',
        'https',
        'stream',
        'url',
        'util',
        'zlib',
        
        // Keep React as external for peer dependencies
        'react',
        'react-dom',
        
        // WebSocket in Node.js
        'ws'
      ],
      
      output: [
        // ES Module build
        {
          format: 'es',
          entryFileNames: '[name].mjs',
          chunkFileNames: 'chunks/[name]-[hash].mjs',
          assetFileNames: 'assets/[name]-[hash][extname]',
          preserveModules: false,
          exports: 'named'
        },
        
        // CommonJS build
        {
          format: 'cjs',
          entryFileNames: '[name].js',
          chunkFileNames: 'chunks/[name]-[hash].js',
          assetFileNames: 'assets/[name]-[hash][extname]',
          preserveModules: false,
          exports: 'named'
        },
        
        // UMD build for CDN usage
        {
          format: 'umd',
          name: 'AMPSdk',
          entryFileNames: '[name].umd.js',
          globals: {
            'react': 'React',
            'react-dom': 'ReactDOM'
          }
        },
        
        // IIFE build for direct browser usage
        {
          format: 'iife',
          name: 'AMPSdk',
          entryFileNames: '[name].iife.js',
          globals: {
            'react': 'React',
            'react-dom': 'ReactDOM'
          }
        }
      ]
    },
    
    // Bundle analysis
    reportCompressedSize: true,
    chunkSizeWarningLimit: 500,
    
    // Source maps
    sourcemap: true,
    
    // Minification
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: false,
        drop_debugger: true
      },
      format: {
        comments: false
      }
    },
    
    // Target
    target: ['es2020', 'node16'],
    
    // Output directory
    outDir: 'dist',
    emptyOutDir: true
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
    __DEV__: JSON.stringify(process.env.NODE_ENV === 'development')
  },
  
  optimizeDeps: {
    include: ['uuid', 'eventemitter3', 'zod', 'jose']
  },
  
  // Environment variables
  envPrefix: ['VITE_', 'AMP_'],
  
  // Server config for development
  server: {
    port: 3000,
    host: true,
    cors: true
  },
  
  // Preview config
  preview: {
    port: 3001,
    host: true,
    cors: true
  }
})