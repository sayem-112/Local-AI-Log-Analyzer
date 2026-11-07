# Start the local model server (Windows). Same flags as scripts/start_model.sh.
#   -c 2048                context window required by the brief
#   -t 2 -tb 2             2 vCPU budget
#   -np 1                  one slot: one call at a time, one KV cache in RAM
#   --reasoning off        Qwen thinking tokens would eat the 2048 budget
#   --cache-ram 0          default is an 8 GB host prompt cache; measured 3.8 GB RSS with it
#   --ctx-checkpoints 8    lets this hybrid model reuse the fixed system-prompt prefix
#                          (2 checkpoints = 0 reuse; 8 = 411 tokens reused per call, ~1.98 GB RSS)
param([string]$Model = "models/Qwen3.5-2B-Q4_K_M.gguf", [int]$Port = 8081)
$root = Split-Path $PSScriptRoot -Parent
& "$root/bin/llama/llama-server.exe" -m "$root/$Model" -c 2048 -t 2 -tb 2 -np 1 --reasoning off --no-mmproj `
    --cache-ram 0 --ctx-checkpoints 8 --host 127.0.0.1 --port $Port
