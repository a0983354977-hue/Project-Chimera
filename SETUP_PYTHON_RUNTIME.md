# Python Runtime Setup

The Python bridge validates Nim's versioned PE feature JSON with Pydantic and optionally scans the original file with `yara-python`.

## System Python

Install the declared dependencies into the Python environment whose DLL nimpy will load:

```batch
python -m pip install -r python_core\requirements.txt
```

Use a 64-bit Python interpreter for a 64-bit Chimera build. Ensure that interpreter's `python3*.dll` is discoverable to nimpy via `PATH`.

## Optional embedded runtime (Windows)

1. Download the Windows embeddable package matching Chimera's architecture and a Python version supported by nimpy and the package wheels.
2. Extract it into `python_runtime\` beside `chimera.exe`.
3. Keep the matching `python3*.dll`, standard-library ZIP, and `_pth` file together.
4. Install `python_core\requirements.txt` into an import directory enabled by the embedded `_pth` configuration. Include that `site-packages` path and enable `import site` when using installed wheels.
5. Keep `python_core\` beside `chimera.exe`.

At startup, Chimera selects a `python*.dll` from `python_runtime\`, adds that directory to the DLL search path, then adds the application directory to Python's module path. If no bundled DLL is present, nimpy uses a compatible system Python discoverable on `PATH`.

## YARA rules

Chimera does not download or bundle third-party rules. Supply a local rule file explicitly:

```batch
chimera.exe --rules path\to\rules.yar path\to\sample.exe
chimera.exe --json --rules path\to\rules.yar --dir path\to\pe-files
chimera.exe --sarif --rules path\to\rules.yar --dir path\to\pe-files
```

Rule compilation and file scanning errors are surfaced; they are not converted into an empty match result.

## SARIF output

`--sarif` writes a SARIF 2.1.0 document to standard output for direct use by compatible CI and code-scanning tools. It includes concrete findings for malformed PE files, analysis failures, high-entropy sections, selected suspicious imports, elevated heuristic scores, and user-supplied YARA matches. SARIF findings are triage signals, not a malware verdict. `--sarif` and `--json` cannot be combined.

## Validation

```batch
chimera.exe --no-ai --json path\to\sample.exe
chimera.exe --json path\to\sample.exe
```

The first validates PE parsing and JSON serialization without Python. The second also verifies Python initialization, Pydantic validation, and heuristic inference.

## Deployment limitation

The current build is not a single-file bundle. Ship `chimera.exe`, `python_core\`, the installed dependencies, and (when using embedded Python) `python_runtime\` together. Python and YARA dependencies have separate licensing and packaging requirements; review them before redistribution.
