# DB-TRACE PowerShell Task Runner
param(
    [Parameter(Position = 0)]
    [ValidateSet("test", "lint", "generate", "train", "api", "demo")]
    [string]$Task = "test"
)

$ErrorActionPreference = "Stop"

switch ($Task) {
    "test"     { uv run pytest }
    "lint"     { uv run ruff check dbtrace tests }
    "generate" { uv run python -m dbtrace.generator --n 100 --seed 42 }
    "train"    { uv run python -m dbtrace.models.train }
    "api"      { uv run uvicorn dbtrace.api.app:app --reload --port 8000 }
    "demo"     {
        uv run python -m dbtrace.generator --n 100 --seed 42
        uv run python -m dbtrace.models.train
        uv run uvicorn dbtrace.api.app:app --port 8000
    }
}
