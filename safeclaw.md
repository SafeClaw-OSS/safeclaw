# SafeClaw Service Registry

Configure your AI agent to use these base URLs instead of calling upstream APIs directly.
SafeClaw injects the real API key from your encrypted vault on each request.

## Proxy Base URL

```
http://localhost:23295       # default (local deployment)
https://your-instance-url   # remote deployment (set SAFECLAW_ADMIN_URL)
```

## Service Routing

| Service | Use this base URL | Instead of |
|---|---|---|
| Anthropic | `{proxy}/anthropic/v1` | `https://api.anthropic.com/v1` |
| OpenAI | `{proxy}/openai/v1` | `https://api.openai.com/v1` |
| Google AI | `{proxy}/google/v1beta` | `https://generativelanguage.googleapis.com/v1beta` |
| Brave Search | `{proxy}/brave/res/v1` | `https://api.search.brave.com/res/v1` |
| DeepSeek | `{proxy}/deepseek/v1` | `https://api.deepseek.com/v1` |
| Groq | `{proxy}/groq/openai/v1` | `https://api.groq.com/openai/v1` |

## Agent Configuration Example

```yaml
# OpenClaw config
providers:
  anthropic:
    baseUrl: http://localhost:23295/anthropic/v1
    apiKey: sk-dummy   # SafeClaw injects the real key
  openai:
    baseUrl: http://localhost:23295/openai/v1
    apiKey: sk-dummy
```

## Custom Services

Additional services configured in your vault are accessible at:
```
{proxy}/{service-name}/...
```

where `{service-name}` matches the name you registered in the SafeClaw console.
