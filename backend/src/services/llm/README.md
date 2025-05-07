# LLM Service

The LLM (Large Language Model) service provides a robust, extensible framework for interacting with various AI language models within the XcelCrowd platform. It is designed with enterprise-grade features including caching, failover, monitoring, and provider abstraction.

## Architecture

The LLM service follows a modular architecture with clear separation of concerns:

```
llm/
├── interfaces/           # Type definitions and interfaces
│   ├── ILLMService.ts    # Main service interface
│   ├── ILLMRequest.ts    # Request/response type definitions
│   └── ILLMProvider.ts   # Provider interface definition
├── providers/            # Implementations for different LLM providers
│   ├── OpenAIProvider.ts # OpenAI API implementation
│   ├── AnthropicProvider.ts # Anthropic API implementation
│   └── AzureOpenAIProvider.ts # Azure OpenAI implementation
├── monitoring/           # Telemetry and observability components
│   ├── LLMMetricsCollector.ts # Usage metrics collection
│   └── LLMLogger.ts      # Specialized logging for LLM operations
├── prompts/              # Pre-defined prompt templates
├── LLMService.ts         # Main service implementation 
└── LLMCache.ts           # Caching implementation
```

## Core Components

### LLMService

The main entry point for all LLM operations. It:
- Manages provider selection and token distribution
- Handles caching of responses
- Provides a unified API for text generation and embeddings
- Implements token counting and context window management
- Handles error recovery and retries

### Provider Implementations

Each provider (OpenAI, Anthropic, Azure OpenAI) implements the `ILLMProvider` interface, allowing:
- Provider-specific API interactions
- Model capability detection
- Provider-specific optimizations
- Error handling and response normalization

### Caching System

The `LLMCache` implements deterministic caching for LLM responses:
- Uses semantic fingerprinting of requests
- Configurable TTL (time-to-live) for cache entries
- Memory-efficient storage with optional persistent backend
- Support for partial matching and cache warming

## Key Workflows

### Text Generation

1. Client calls `LLMService.generateText()` with a request payload
2. Service validates the request and checks cache
3. If cache hit, returns cached response
4. Otherwise, determines appropriate provider for the requested model
5. Forwards request to selected provider
6. Provider calls the external API with appropriate formatting
7. Response is processed, normalized, and cached
8. Metrics are recorded
9. Response is returned to client

### Streaming Generation

For streaming responses, the workflow is similar but uses async generators:
1. Client initiates stream with `LLMService.generateTextStream()`
2. Service creates a stream connection to the appropriate provider
3. As chunks arrive, they are yielded to the client
4. Metrics are accumulated and recorded at stream completion

### Embedding Generation

For generating embeddings (vector representations of text):
1. Client calls `LLMService.generateEmbedding()`
2. Service routes to an embedding-capable provider
3. Provider returns vector representations
4. Results are cached and returned

## Error Handling and Reliability

The service implements sophisticated error handling:
- Circuit breaking to prevent repeated failures
- Automatic failover between providers
- Token rotation when rate limits are approached
- Graceful degradation when services are unavailable
- Detailed error classification and logging

## Configuration

LLM service configuration is managed through environment variables:
- API keys for different providers
- Default model selections
- Cache settings
- Rate limiting parameters
- Monitoring configuration

## Usage Example

```typescript
import { LLMService } from '../services/llm/LLMService';

async function analyzeCode(code: string): Promise<string> {
  const llmService = LLMService.getInstance();
  
  const response = await llmService.generateText({
    model: 'gpt-4o', // Will automatically select appropriate provider
    messages: [
      { role: 'system', content: 'You are a code analysis expert.' },
      { role: 'user', content: `Analyze this code:\n\`\`\`\n${code}\n\`\`\`` }
    ],
    temperature: 0.2,
    maxTokens: 1000,
    metadata: {
      source: 'code-analysis',
      purpose: 'quality-check'
    }
  });
  
  return response.text;
}
```

## Integration with AI Agents

The LLM service is the foundation for the AI agent system:
1. All AI agents use the LLM service for their reasoning and analysis
2. The service provides consistent handling of API limits and errors
3. Caching improves response times for similar requests
4. Usage metrics help optimize token consumption

## Monitoring and Performance

The service includes detailed monitoring:
- Request volume, latency, and token usage tracking
- Cost estimation based on token consumption
- Error rate monitoring with provider breakdown
- Cache hit ratio and efficiency metrics

## Extensibility

Adding a new LLM provider requires:
1. Creating a new provider class implementing `ILLMProvider`
2. Registering the provider in the LLMService
3. Adding appropriate configuration options

This architecture allows the platform to quickly adapt to new LLM offerings while maintaining a consistent interface for all components that rely on AI capabilities. 