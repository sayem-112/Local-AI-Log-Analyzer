# One-time setup (Windows). Needs internet; everything after this runs offline.
#   powershell -ExecutionPolicy Bypass -File scripts/setup.ps1            # 2B model (default)
#   powershell -ExecutionPolicy Bypass -File scripts/setup.ps1 -Small     # also fetch the 0.8B model
param([switch]$Small)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$root = Split-Path $PSScriptRoot -Parent
$build = "b12182"  # pinned llama.cpp release that was tested

py -3.12 -m venv "$root/.venv"
& "$root/.venv/Scripts/python" -m pip install -q -r "$root/requirements.txt"

if (-not (Test-Path "$root/bin/llama/llama-server.exe")) {
    New-Item -ItemType Directory -Force "$root/bin/llama" | Out-Null
    $zip = "$root/bin/llama.zip"
    Invoke-WebRequest "https://github.com/ggml-org/llama.cpp/releases/download/$build/llama-$build-bin-win-cpu-x64.zip" -OutFile $zip
    Expand-Archive $zip -DestinationPath "$root/bin/llama" -Force
    Remove-Item $zip
}

New-Item -ItemType Directory -Force "$root/models" | Out-Null
$models = @("Qwen3.5-2B-Q4_K_M.gguf")
if ($Small) { $models += "Qwen3.5-0.8B-Q4_K_M.gguf" }
foreach ($m in $models) {
    $repo = if ($m -like "*0.8B*") { "unsloth/Qwen3.5-0.8B-GGUF" } else { "unsloth/Qwen3.5-2B-GGUF" }
    if (-not (Test-Path "$root/models/$m")) {
        Write-Host "Downloading $m ..."
        Invoke-WebRequest "https://huggingface.co/$repo/resolve/main/$m" -OutFile "$root/models/$m"
    }
}
Write-Host "Setup done. Start the model: scripts/start_model.ps1   Then the app: .venv/Scripts/python -m uvicorn app.main:app --port 8000"
