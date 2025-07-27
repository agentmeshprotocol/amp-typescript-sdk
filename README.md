# Agent Mesh Protocol TypeScript SDK

[![npm version](https://badge.fury.io/js/@agentmesh/amp-sdk.svg)](https://badge.fury.io/js/@agentmesh/amp-sdk)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

The official TypeScript/JavaScript SDK for the Agent Mesh Protocol (AMP), enabling seamless integration of AI agents in web and Node.js environments.

## 🚀 Features

- **Type Safety**: Full TypeScript support with comprehensive type definitions
- **Framework Agnostic**: Works with any JavaScript framework or vanilla JS
- **Browser & Node.js**: Universal package for both environments
- **Modern APIs**: Promise-based with async/await support
- **Transport Options**: HTTP, WebSocket, and custom transport support
- **Real-time**: Built-in WebSocket support for real-time agent communication

## 📦 Installation

```bash
# npm
npm install @agentmesh/amp-sdk

# yarn
yarn add @agentmesh/amp-sdk

# pnpm
pnpm add @agentmesh/amp-sdk
```

## 🏃 Quick Start

### Basic Usage

```typescript
import { AMPClient, AMPClientConfig, TransportType } from '@agentmesh/amp-sdk';

// Configure your agent
const config: AMPClientConfig = {
  agentId: 'my-typescript-agent',
  agentName: 'My TypeScript Agent',
  transportType: TransportType.HTTP,
  endpoint: 'http://localhost:8000'
};

// Create and connect
const client = new AMPClient(config);

async function main() {
  await client.connect();
  
  // Register a capability
  await client.registerCapability({
    id: 'text-analysis',
    handler: async (params: { text: string }) => {
      return {
        sentiment: params.text.includes('good') ? 'positive' : 'neutral',
        confidence: 0.85
      };
    },
    schema: {
      input: {
        type: 'object',
        properties: { text: { type: 'string' } },
        required: ['text']
      },
      output: {
        type: 'object',
        properties: {
          sentiment: { type: 'string' },
          confidence: { type: 'number' }
        }
      }
    }
  });
  
  // Invoke another agent's capability
  const result = await client.invokeCapability({
    targetAgent: 'other-agent',
    capability: 'summarization',
    parameters: { text: 'Long text to summarize...' }
  });
  
  console.log('Summary:', result);
}

main().catch(console.error);
```

### React Integration

```tsx
import React, { useEffect, useState } from 'react';
import { AMPClient, AMPClientConfig } from '@agentmesh/amp-sdk';

function AgentComponent() {
  const [client, setClient] = useState<AMPClient | null>(null);
  const [result, setResult] = useState<any>(null);
  
  useEffect(() => {
    const config: AMPClientConfig = {
      agentId: 'react-agent',
      agentName: 'React Agent',
      transportType: 'websocket',
      endpoint: 'ws://localhost:8000'
    };
    
    const ampClient = new AMPClient(config);
    ampClient.connect().then(() => {
      setClient(ampClient);
    });
    
    return () => {
      ampClient.disconnect();
    };
  }, []);
  
  const handleAnalyze = async () => {
    if (!client) return;
    
    const result = await client.invokeCapability({
      capability: 'sentiment-analysis',
      parameters: { text: 'This is amazing!' }
    });
    
    setResult(result);
  };
  
  return (
    <div>
      <button onClick={handleAnalyze} disabled={!client}>
        Analyze Sentiment
      </button>
      {result && <div>Result: {JSON.stringify(result, null, 2)}</div>}
    </div>
  );
}
```

### Node.js Server

```typescript
import express from 'express';
import { AMPClient, AMPClientConfig } from '@agentmesh/amp-sdk';

const app = express();
const port = 3000;

const config: AMPClientConfig = {
  agentId: 'express-agent',
  agentName: 'Express Server Agent',
  transportType: 'http',
  endpoint: 'http://localhost:8000'
};

const client = new AMPClient(config);

app.post('/analyze', async (req, res) => {
  try {
    const result = await client.invokeCapability({
      capability: 'text-analysis',
      parameters: req.body
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

async function startServer() {
  await client.connect();
  
  app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
  });
}

startServer().catch(console.error);
```

## 📚 API Reference

### AMPClient

The main client class for AMP communication.

```typescript
class AMPClient {
  constructor(config: AMPClientConfig);
  
  // Connection management
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  isConnected(): boolean;
  
  // Capability management
  registerCapability(capability: CapabilityDefinition): Promise<void>;
  unregisterCapability(capabilityId: string): Promise<void>;
  
  // Communication
  invokeCapability(request: CapabilityRequest): Promise<any>;
  emitEvent(eventType: string, data: any): Promise<void>;
  
  // Event handling
  on(event: string, handler: Function): void;
  off(event: string, handler?: Function): void;
}
```

### Types

```typescript
interface AMPClientConfig {
  agentId: string;
  agentName: string;
  transportType: TransportType;
  endpoint: string;
  apiKey?: string;
  timeout?: number;
  autoReconnect?: boolean;
}

enum TransportType {
  HTTP = 'http',
  WEBSOCKET = 'websocket'
}

interface CapabilityDefinition {
  id: string;
  handler: CapabilityHandler;
  schema: CapabilitySchema;
  constraints?: CapabilityConstraints;
}

type CapabilityHandler = (params: any) => Promise<any>;
```

## 🔧 Configuration

### Environment Variables

```bash
# Basic configuration
VITE_AMP_AGENT_ID=my-agent          # For Vite
REACT_APP_AMP_AGENT_ID=my-agent     # For Create React App
AMP_ENDPOINT=http://localhost:8000   # For Node.js
AMP_API_KEY=your-api-key
```

### Advanced Configuration

```typescript
const config: AMPClientConfig = {
  agentId: 'advanced-agent',
  agentName: 'Advanced Agent',
  transportType: TransportType.WEBSOCKET,
  endpoint: 'wss://amp.example.com',
  apiKey: process.env.AMP_API_KEY,
  timeout: 30000,
  autoReconnect: true,
  retryAttempts: 3,
  retryDelay: 1000,
  heartbeatInterval: 30000
};
```

## 🧪 Testing

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run integration tests
npm run test:integration

# Run in watch mode
npm run test:watch
```

### Test Example

```typescript
import { AMPClient } from '@agentmesh/amp-sdk';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

describe('AMPClient', () => {
  let client: AMPClient;
  
  beforeEach(async () => {
    client = new AMPClient({
      agentId: 'test-agent',
      agentName: 'Test Agent',
      transportType: 'http',
      endpoint: 'http://localhost:8000'
    });
    await client.connect();
  });
  
  afterEach(async () => {
    await client.disconnect();
  });
  
  it('should register a capability', async () => {
    await client.registerCapability({
      id: 'test-capability',
      handler: async () => ({ success: true }),
      schema: { input: {}, output: {} }
    });
    
    expect(client.hasCapability('test-capability')).toBe(true);
  });
});
```

## 🏗️ Building

```bash
# Build for production
npm run build

# Build for development
npm run build:dev

# Watch mode for development
npm run build:watch

# Type checking
npm run type-check
```

## 📊 Monitoring

```typescript
import { AMPClient, AMPMetrics } from '@agentmesh/amp-sdk';

const client = new AMPClient(config);

// Enable metrics collection
client.enableMetrics({
  endpoint: 'http://metrics.example.com',
  interval: 30000
});

// Listen to events
client.on('message:sent', (message) => {
  console.log('Message sent:', message.id);
});

client.on('capability:invoked', (capability) => {
  console.log('Capability invoked:', capability.id);
});

client.on('error', (error) => {
  console.error('AMP Error:', error);
});
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](../../CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/agentmeshprotocol/amp-typescript-sdk.git
cd amp-typescript-sdk
npm install
npm run dev
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- [GitHub Issues](https://github.com/agentmeshprotocol/amp-typescript-sdk/issues)
- [Documentation](https://docs.agentmeshprotocol.io/typescript-sdk)
- [Discord Community](https://discord.gg/agentmeshprotocol)

---

**Maintained by [MeshAI Labs](https://meshai.dev)**