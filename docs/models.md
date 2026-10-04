# Model Providers

Tier, patch and every validation flag are computed before any model is consulted. A
model writes prose only. Absent a credential the narrative degrades to deterministic
text and the service continues to triage, route and answer `/healthz`.

| `LLM_PROVIDER` | Credential | Default endpoint | Protocol | Live-verified |
|---|---|---|---|---|
| `gemini` | `GEMINI_API_KEY` | Google AI Studio | Gemini | yes |
| `anthropic` | `ANTHROPIC_API_KEY` | Anthropic Messages | Messages, forced tool-use | no |
| `openai` | `OPENAI_API_KEY` | OpenAI | OpenAI chat-completions | no |
| `openrouter` | `OPENROUTER_API_KEY` | `openrouter.ai/api/v1` | OpenAI chat-completions | no |
| `groq` | `GROQ_API_KEY` | `api.groq.com/openai/v1` | OpenAI chat-completions | no |
| `deepseek` | `DEEPSEEK_API_KEY` | `api.deepseek.com/v1` | OpenAI chat-completions | no |
| `nvidia` | `NVIDIA_API_KEY` | `integrate.api.nvidia.com/v1` | OpenAI chat-completions | yes |
| `ollama` | none required | `localhost:11434/v1` | OpenAI chat-completions | no |
| `vllm` | none required | `localhost:8000/v1` | OpenAI chat-completions | no |

Live-verified means a real credential, a real endpoint and a real response. All nine
are covered by an offline suite that drives the actual SDK over a mock transport, so
the request shape, the auth header, the retry classification and the reply parsing are
asserted against what the SDK builds and accepts rather than against a
re-implementation. For an unverified row, the first real call is the test. A wrong
model id or an unusable token budget presents as no narrative at all, which is the
fail-closed path behaving correctly; the startup line names the resolved provider and
model.

| Variable | Default | Effect |
|---|---|---|
| `LLM_PROVIDER` | `gemini` | One of the nine above. An unrecognised value falls back to `gemini` with a startup warning rather than refusing to start. |
| `LLM_BASE_URL` | the provider's own | Overrides the endpoint: an LM Studio server, a corporate gateway, a private endpoint. |
| `LLM_MODEL` | per provider | The provider-specific pin — `ANTHROPIC_MODEL`, `GROQ_MODEL`, `VLLM_MODEL` — takes precedence. |

### Credential mounting

`deploy/agent.yaml` ships `LLM_PROVIDER` and mounts a credential reference for
`GEMINI_API_KEY` and `NVIDIA_API_KEY` only. Selecting a different provider requires
editing that file to mount the corresponding `[PROVIDER]_API_KEY` from the
`srek3s-secrets` Secret. Setting `LLM_PROVIDER: anthropic` alone yields
`ANTHROPIC_API_KEY is not set`, which reads as a missing Secret rather than a missing
manifest entry.

```yaml
- name: ANTHROPIC_API_KEY
  valueFrom:
    secretKeyRef:
      name: srek3s-secrets
      key: ANTHROPIC_API_KEY
      optional: true
```

References are not mounted in bulk. Every mounted reference is a credential readable
inside the Agent container, so a deployment mounts the one it uses; a cluster switched
to `groq` gains nothing from `NVIDIA_API_KEY` being readable in its pod. `ollama` and
`vllm` require no reference at all.

`optional: true` is required on every reference. Without it a cluster holding no
Secret produces pods stuck in `CreateContainerConfigError`, and an installation that
wants no model cannot start.

### Behaviour

A credential is never accepted by a provider it does not belong to. `OPENAI_API_KEY`
does not authenticate `anthropic`; `ANTHROPIC_API_KEY` does not authenticate `groq`.
An unrecognised credential degrades to deterministic prose rather than reaching a third
party. To use one OpenAI-shaped credential against an aggregator, set
`LLM_PROVIDER=openai` with `LLM_BASE_URL` pointed at that aggregator.

Provider defaults are models confirmed against a live service at the time of writing.
Pin `ANTHROPIC_MODEL`, `NVIDIA_MODEL` and the rest: providers retire models, and a
retired identifier presents as no model configured rather than as an error.

`vllm` carries no default model. A vLLM server serves whatever the operator launched,
so an unset `VLLM_MODEL` is refused before any request, naming the variable to set.

## Model adapter behaviour

Each adapter isolates the rules from the evidence using its own protocol's mechanism:
`system_instruction` for Gemini, a `system` message role for the OpenAI chat-completions
protocol, a forced tool call with the schema as `input_schema` for Anthropic.

The Anthropic Messages API has no `response_format` parameter, so the permitted slice
is enforced by forcing one tool whose `input_schema` is built from
`llm.NARRATIVE_FIELDS`. The same SDK has no `temperature` parameter, so that adapter
does not pin it and does not claim determinism.

Both adapters are driven in tests through the real SDK over a mock transport. The
`anthropic` package is built on `httpx2` and rejects an `httpx.Client`; `openai` uses
`httpx`.

Retry policy is narrow and shared: at most 3 attempts, 1.5 s apart, and only for
provider load-shedding and gateway timeouts. A 429 is not retried — only
`RESOURCE_EXHAUSTED` distinguishes an exhausted quota from a momentary rate limit, and
three retries cannot restore a quota. A refusal, a malformed reply, or freeform output
is never retried; it degrades to deterministic prose.

A missing credential, an absent endpoint and a retired model identifier present
identically from outside: no narrative. The startup line names the resolved provider
and model, which is the first thing to read.
