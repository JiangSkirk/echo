# Speculative decoding (P3-3)

Pure configuration. JS Agent does not implement a draft-model sampler.
Ollama and LM Studio can run speculative / draft decoding **inside the
local server**. Point `draft_model` at a smaller sibling of the target
model; leave it `null` (the default) to keep current decoding.

This is not on the production path unless the operator sets it on a
local provider. Cloud providers should leave `draft_model` unset.

## Ollama

Ollama reads draft models from Modelfile / server config. Example Host
provider block (URLs already used by the setup wizard):

```yaml
providers:
  - name: ollama
    base_url: http://127.0.0.1:11434/v1
    api_key: ollama
    default_model: llama3.2
    draft_model: llama3.2:1b   # optional; null = off
```

On the Ollama side, enable speculative decoding for that pair (see
Ollama's current draft-model docs). JS Agent only stores the id.

## LM Studio

```yaml
providers:
  - name: lmstudio
    base_url: http://127.0.0.1:1234/v1
    api_key: lm-studio
    default_model: local-lm
    draft_model: local-draft    # optional; must be loaded in LM Studio
```

LM Studio's speculative decoding is a server setting. The Host does not
send a draft model in OpenAI-compatible chat payloads.

## Defaults

- `ModelConfig.draft_model` / `ModelProviderConfig.draft_model` default to `null`.
- Router `select_model` / `chat` ignore the field.
- Setup wizard still only probes `127.0.0.1:1234` and `11434`; it does not enable draft models.
