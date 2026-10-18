# Project Chimera

Project Chimera is a Windows command-line PE triage utility written in Nim with a Python validation, heuristic, and optional YARA bridge.

## Features

- Maps PE files read-only and validates DOS, NT, COFF, optional, section, and import structures before accessing them.
- Supports PE32 and PE32+, maps RVAs through headers and sections, extracts section names/import names, and calculates raw-section Shannon entropy.
- Rejects malformed or out-of-range structures with an explicit error instead of returning success-shaped empty data.
- Emits versioned JSON with `--json`; Python validates the PE feature document with Pydantic before analysis.
- Emits SARIF 2.1.0 with `--sarif`, including parse errors, high-entropy sections, selected suspicious imports, elevated heuristic scores, and user-supplied YARA matches.
- Scans `.exe` and `.dll` files from a directory in bounded task-pool batches; Python inference and YARA matching stay on the main thread.
- Supports a user-supplied YARA rules file; no third-party rule set is downloaded or bundled.
- Can list process IDs using the Windows ToolHelp API. It does not read arbitrary process memory.
- Runs deterministic Python heuristics that return a **risk score**, not a calibrated probability or machine-learning prediction.
- Maps Nim-extracted PE features (imports, sections, entropy) to **MITRE ATT&CK techniques** (TTPs), reconstructs the attack kill chain, and emits a tactical threat summary.
- Extracts hardcoded **Indicators of Compromise** (IPv4, URLs, PDB paths, sensitive execution strings) from raw PE bytes; included in JSON and SARIF output.
- Maintains a SQLite **sample fingerprint** database (`chimera_cache.sqlite3`) for XXHash content fingerprinting, analysis result caching, and cross-sample structural similarity correlation with variant attribution hints.
- Can generate a combined Markdown or HTML threat intelligence report with `--report <path>` and `--report-format <markdown|html>`.
- Supports a **daemon mode** (`--daemon`) that keeps the Python bridge and YARA rules resident, accepting JSON requests on stdin and emitting JSON results on stdout, eliminating per-process Python startup overhead for bulk scans.
- Ships **Chimera-Vision**, a zero-dependency local web dashboard (`--gui`) that drives the daemon over the same stdio IPC and renders sections/entropy, the MITRE ATT&CK kill chain, the imports/IOC grid, and one-click SARIF/HTML export.
- Can use a Python runtime in `python_runtime\` or a compatible system Python installation.

## Build

Requirements: Nim 2.x, nimble, Windows, and Python dependencies from `python_core\requirements.txt`. The bridge requires a Python DLL compatible with nimpy; using the same architecture as the Nim executable is mandatory.

```batch
nimble install -y nimpy taskpools winim
python -m pip install -r python_core\requirements.txt
build.bat
```

`build.bat` creates `chimera.exe` with Nim threads enabled. The batch parser uses the maintained `taskpools` package rather than Nim's deprecated standard-library `threadpool`. Keep `python_core\` and installed dependencies available to the interpreter beside the executable. To use the embeddable runtime, place the matching Python embeddable distribution in `python_runtime\` and install both requirements into its import path. Otherwise, nimpy attempts to load a compatible system Python discoverable on `PATH`.

This is a portable directory layout, not a single-file executable: nimpy dynamically loads the Python DLL and the inference script. A true single-file bundle needs an extraction/loader design and is not produced by this build.

## Usage

```batch
chimera.exe path\to\sample.exe
chimera.exe --no-ai path\to\sample.exe
chimera.exe --json path\to\sample.exe
chimera.exe --sarif path\to\sample.exe
chimera.exe --report path\to\report.md path\to\sample.exe
chimera.exe --report path\to\report.html --report-format html path\to\sample.exe
chimera.exe --daemon [--no-ai] [--no-cache] [--rules rules.yar]
chimera.exe --gui [--rules rules.yar] [path\to\sample.exe]
chimera.exe --rules path\to\rules.yar path\to\sample.exe
chimera.exe --json --dir path\to\pe-files
chimera.exe --sarif --dir path\to\pe-files
chimera.exe --no-ai --json --dir path\to\pe-files
chimera.exe --list-processes
chimera.exe --help
```

Directory scans are non-recursive and include only `.exe` and `.dll` files. PE mapping and entropy parsing run concurrently in a bounded `taskpools` worker pool; Python validation, heuristics, and YARA matching run serially on the main thread. Batch results preserve sorted path order. Invalid files appear as explicit error records, and any failed record makes the command exit non-zero.

Nim computes a 64-bit XXHash content fingerprint for every parsed file, and a user-supplied YARA rule file is compiled once per run instead of once per sample. When Python is enabled, analysis results are cached in a SQLite database (`chimera_cache.sqlite3` beside the executable) keyed by that fingerprint, the rules fingerprint, and an engine version, so re-scanning identical or repeated files returns byte-identical results without recomputing heuristics, TTP mapping, or YARA matches. Pass `--no-cache` to bypass the result cache; the rules are still compiled only once per run.

JSON output has a top-level `schema_version` and a `results` array. Successful records contain `file_path`, `status`, `architecture`, `sections` (name and entropy), `imports`, and, when Python is enabled, `analysis` (`risk_score`, `yara_matches`). PE failures use `status: "error"`; Python initialization/inference failures use `status: "analysis_error"`. Both contain an `error` message and cause a non-zero exit status.

SARIF output follows version 2.1.0. It reports malformed PE files and Python analysis failures as errors; high-entropy sections, selected suspicious imports, heuristic risk scores at or above 0.500, explicit YARA matches, and hardcoded IOC detections are warnings. `--sarif` and `--json` are mutually exclusive. SARIF does not imply a clean verdict when no results are reported.

The file is opened read-only and is never executed. Without `--no-ai`, failures to load Python or run inference are reported and return a non-zero exit code; no neutral score is substituted. `--rules` requires Python and an explicit YARA rule file.

## Chimera-Vision dashboard

`chimera.exe --gui [sample.exe]` starts a local dashboard and returns immediately; a browser tab opens at `http://127.0.0.1:8765/`, and an optional path argument is preloaded. Running `--gui` again while one is already listening reuses it instead of starting a second instance.

The dashboard is a single stdlib-only Python process (`python_core\dashboard.py`) serving `python_core\dashboard_ui.html`. It does **not** import pydantic or yara: on the first request it spawns a persistent `chimera.exe --daemon` child and speaks the same JSON-lines stdio IPC used by daemon mode, so analysis reuses the resident Python bridge, the compiled YARA rules, and the SQLite result cache. It can also be run directly:

```batch
python python_core\dashboard.py [--port 8765] [--rules rules.yar] [--open sample.exe] [--no-browser]
```

The four quadrants show, for the selected sample: section entropy bars with sections at or above 7.2 flagged as possibly packed or encrypted; the MITRE ATT&CK kill chain grouped by phase; a searchable imports table with high-risk APIs highlighted alongside copyable IOC cards; and the raw IPC packet stream with one-click SARIF 2.1.0, HTML report, or JSON export. Files can be dragged onto the window (uploaded to a local temporary directory for scanning) or scanned in place by typing one or more paths separated by `;`.

Python 3 is required. The dashboard itself needs no third-party packages, so any Python 3 interpreter works even when the analysis stack lives in `python_runtime\`. The launcher prefers `python_runtime\python.exe` when present and otherwise uses `python` from `PATH`.

## Safety and scope

The process feature enumerates PIDs only. Arbitrary process-memory reading, string obfuscation, dead-code insertion, randomized binaries, and anti-detection behavior are intentionally not included. YARA rules are supplied by the operator and are not fetched automatically. PE entropy, import heuristics, and YARA matches are triage signals and must not be treated as a malware verdict.

## License

Project Chimera is distributed under the MIT License. See [LICENSE](LICENSE).
