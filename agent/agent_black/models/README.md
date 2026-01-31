# Local Models

Drop your GGUF model files here. They are gitignored so each user can choose their own.

## Recommended Models

| Model | Size | Use Case |
|-------|------|----------|
| `dolphin-mistral-7b.Q4_K_M.gguf` | ~4GB | Best balance of speed/quality |
| `dolphin-mistral-7b.Q5_K_M.gguf` | ~5GB | Higher quality, slower |
| `mistral-7b-instruct.Q4_K_M.gguf` | ~4GB | General purpose |
| `codellama-7b.Q4_K_M.gguf` | ~4GB | Code-focused tasks |

## Download

**Dolphin Mistral 7B (recommended):**
```bash
# Using huggingface-cli
huggingface-cli download TheBloke/dolphin-2.2.1-mistral-7B-GGUF dolphin-2.2.1-mistral-7b.Q4_K_M.gguf --local-dir .

# Or direct download
wget https://huggingface.co/TheBloke/dolphin-2.2.1-mistral-7B-GGUF/resolve/main/dolphin-2.2.1-mistral-7b.Q4_K_M.gguf
```

**Or use Ollama instead (no download needed):**
```bash
ollama pull dolphin-mistral
ollama pull mistral
```

## File Structure

```
models/
├── README.md                              # This file
├── dolphin-2.2.1-mistral-7b.Q4_K_M.gguf   # Your model (gitignored)
└── manifest.json                          # Optional: custom config
```

## Usage

Agent BLACK auto-detects models in this folder:

```bash
python scripts/black_chat.py --list-models
python scripts/black_chat.py --model dolphin-2.2.1-mistral-7b.Q4_K_M.gguf
```

Or it will use Ollama if no local model is found and Ollama is running.

## Requirements

For local GGUF models:
```bash
pip install llama-cpp-python
```

For GPU acceleration:
```bash
CMAKE_ARGS="-DLLAMA_CUDA=on" pip install llama-cpp-python --force-reinstall --no-cache-dir
```
