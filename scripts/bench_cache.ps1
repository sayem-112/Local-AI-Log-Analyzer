# Compare llama-server cache settings: RAM vs prompt-prefix reuse, on 4 real parts.
# Usage: powershell -File scripts/bench_cache.ps1 -Model models/Qwen3.5-2B-Q4_K_M.gguf
param([string]$Model = "models/Qwen3.5-2B-Q4_K_M.gguf")
$root = Split-Path $PSScriptRoot -Parent
$settings = @("--cache-ram 0 --ctx-checkpoints 2", "--cache-ram 0 --ctx-checkpoints 8", "--cache-ram 256 --ctx-checkpoints 8")
foreach ($s in $settings) {
    Stop-Process -Name llama-server -Force -ErrorAction SilentlyContinue; Start-Sleep 1
    $args = "-m $root/$Model -c 2048 -t 2 -tb 2 -np 1 --reasoning off --no-mmproj --host 127.0.0.1 --port 8081 $s"
    $p = Start-Process "$root/bin/llama/llama-server.exe" -ArgumentList $args -PassThru -WindowStyle Hidden -RedirectStandardError "$root/data/bench_srv.log"
    for ($i = 0; $i -lt 60; $i++) { try { if ((Invoke-WebRequest http://127.0.0.1:8081/health -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) { break } } catch {}; Start-Sleep 1 }
    $out = & "$root/.venv/Scripts/python" "$root/scripts/try_chunks.py" "$root/Cultive8_Workspace_Agrigen_Server.log" --only 3,4,5,6 --no-judge 2>&1 | Select-String "== part"
    $rss = [math]::Round((Get-Process -Id $p.Id).WorkingSet64 / 1MB)
    "`n### $s  (model RSS after: $rss MB)"; $out | ForEach-Object { $_.Line }
}
