# VD_Trajectory
Extract trajectories of an agent with vulnerability detection task

## Environment
### Docker Container-based Ollama Environment
```bash
docker run -d --name ollama --gpus all -p 11434:11434 ollama/ollama
```

### Model Installation
```bash
ollama pull llama3.2
```

### CPU Mode
```bash
docker run -d --name ollama -p 11434:11434 -e OLLAMA_RUNNERS=cpu ollama/ollama
```

### Ollama API Test
```bash
curl http://localhost:11434/api/generate -d '{"model": "llama3.2", "prompt": "hello"}'
```

### Changing Context Limit
```bash
docker run -d --name ollama --gpus all -p 11434:11434 -e OLLAMA_MAX_CTX=50000 ollama/ollama
docker run -d --name ollama -p 11434:11434 -e OLLAMA_RUNNERS=cpu -e OLLAMA_MAX_CTX=50000 ollama/ollama
```