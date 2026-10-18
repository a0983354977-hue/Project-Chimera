import std/[algorithm, cpuinfo, json, net, os, osproc, strformat, strutils, uri, streams]
import ai_bridge
import core_parser
import process_telemetry
import taskpools

type
  CliOptions = object
    targetPath: string
    directoryPath: string
    rulesPath: string
    reportPath: string
    reportFormat: string
    usePython: bool
    outputJson: bool
    outputSarif: bool
    showProcesses: bool
    noCache: bool
    daemon: bool
    gui: bool

proc printUsage() =
  echo "Project Chimera - PE analysis and process inventory"
  echo "Usage:"
  echo "  chimera.exe [--json|--sarif|--report <path>] [--no-ai] [--no-cache] [--rules rules.yar] <file.exe|file.dll>"
  echo "  chimera.exe [--json|--sarif|--report <path>] [--no-ai] [--no-cache] [--rules rules.yar] --dir <directory>"
  echo "  chimera.exe --daemon [--no-ai] [--no-cache] [--rules rules.yar]"
  echo "  chimera.exe --gui [--rules rules.yar] [<file.exe|file.dll>]"
  echo "  chimera.exe --list-processes"
  echo "  chimera.exe --help"
  echo ""
  echo "Daemon mode: reads JSON requests (one per line) on stdin, writes JSON results on stdout."
  echo "  Request: {\"file_path\": \"...\", \"rules_path\": \"...\", \"no_cache\": false}"
  echo ""
  echo "Gui mode: starts the Chimera-Vision web dashboard in the background."
  echo "  Requires python_core\\dashboard.py and a Python 3 interpreter (bundled python_runtime\\ or PATH)."

proc listProcesses() =
  for processId in enumProcesses():
    echo processId

proc featureDocument(filePath: string, features: PEFeatures): JsonNode =
  result = %*{
    "schema_version": 1,
    "file_path": filePath,
    "architecture": (if features.is64Bit: "PE32+" else: "PE32"),
    "sections": newJArray(),
    "imports": %features.imports
  }
  for index, sectionName in features.sections:
    result["sections"].add(%*{
      "name": sectionName,
      "entropy": features.entropyScores[index]
    })

proc parseRecord(filePath: string): string {.gcsafe.} =
  try:
    let features = parsePEFile(filePath)
    result = $(%*{
      "schema_version": 1,
      "file_path": filePath,
      "status": "ok",
      "architecture": (if features.is64Bit: "PE32+" else: "PE32"),
      "content_hash": features.contentHash,
      "sections": featureDocument(filePath, features)["sections"],
      "imports": %features.imports,
      "iocs": %features.iocs
    })
  except CatchableError as error:
    result = $(%*{
      "schema_version": 1,
      "file_path": filePath,
      "status": "error",
      "error": error.msg
    })

proc collectPeFiles(directoryPath: string): seq[string] =
  if not dirExists(directoryPath):
    raise newException(IOError, "Directory not found: " & directoryPath)
  for kind, path in walkDir(directoryPath):
    if kind == pcFile:
      let extension = splitFile(path).ext.toLowerAscii()
      if extension == ".exe" or extension == ".dll":
        result.add(path)
  result.sort()
  if result.len == 0:
    raise newException(IOError, "No .exe or .dll files found in: " & directoryPath)

proc formatHuman(record: JsonNode) =
  let filePath = record["file_path"].getStr()
  if record["status"].getStr() == "error":
    echo "[ERROR] " & filePath & ": " & record["error"].getStr()
    return

  echo fmt"[FILE] {filePath}"
  echo "[FORMAT] " & record["architecture"].getStr()
  let sections = record["sections"]
  echo fmt"[SECTIONS] {sections.len}"
  for section in sections:
    let sectionName = section["name"].getStr()
    let entropy = section["entropy"].getFloat()
    echo fmt"  {sectionName}: entropy {entropy:.3f}"
  let imports = record["imports"]
  echo fmt"[IMPORTS] {imports.len}"
  for imported in imports:
    echo fmt"  {imported.getStr()}"
  if record.hasKey("analysis"):
    let analysis = record["analysis"]
    let riskScore = analysis["risk_score"].getFloat()
    echo fmt"[RISK SCORE] {riskScore:.3f}"
    let yaraMatches = analysis["yara_matches"]
    echo fmt"[YARA MATCHES] {yaraMatches.len}"
    for match in yaraMatches:
      let rule = match["rule"].getStr()
      let ruleNamespace = match["namespace"].getStr()
      echo fmt"  {rule} ({ruleNamespace})"
  else:
    echo "[AI] Skipped (--no-ai)"
  if record.hasKey("analysis"):
    let analysis = record["analysis"]
    if analysis.hasKey("mitre_ttps"):
      let ttps = analysis["mitre_ttps"]
      if ttps.len > 0:
        echo "[MITRE TTPs]"
        for ttp in ttps:
          let tid = ttp["technique_id"].getStr()
          let tname = ttp["technique_name"].getStr()
          let tactic = ttp["tactic"].getStr()
          let conf = ttp["confidence"].getFloat()
          let phase = ttp["kill_chain_phase"].getStr()
          echo fmt"  [{tid}] {tname} — {tactic} (confidence {conf:.2f}, {phase})"
    if analysis.hasKey("tactical_summary"):
      let tsum = analysis["tactical_summary"]
      if tsum.hasKey("summary_text"):
        let summaryText = tsum["summary_text"].getStr()
        echo fmt"[SUMMARY] {summaryText}"
  if record.hasKey("iocs"):
    let iocs = record["iocs"]
    if iocs.len > 0:
      echo fmt"[IOCS] {iocs.len}"
      for ioc in iocs:
        echo fmt"  {ioc.getStr()}"
  if record.hasKey("analysis"):
    let analysis = record["analysis"]
    if analysis.hasKey("family_correlation"):
      let fc = analysis["family_correlation"]
      if fc.hasKey("similar") and fc["similar"].getBool():
        if fc.hasKey("attribution_hint"):
          let hint = fc["attribution_hint"].getStr()
          echo fmt"[FAMILY] {hint}"

const SarifRuleIds = [
  "CHIMERA-PE-INVALID",
  "CHIMERA-ANALYSIS-ERROR",
  "CHIMERA-ENTROPY-HIGH",
  "CHIMERA-IMPORT-SUSPICIOUS",
  "CHIMERA-YARA-MATCH",
  "CHIMERA-RISK-ELEVATED",
  "CHIMERA-IOC-DETECTED"
]

proc sarifRuleIndex(ruleId: string): int =
  for index, candidate in SarifRuleIds:
    if candidate == ruleId:
      return index
  raise newException(ValueError, "Unknown SARIF rule identifier: " & ruleId)

proc sarifUri(filePath: string): string =
  let normalizedPath = filePath.replace('\\', '/')
  if normalizedPath.len >= 3 and normalizedPath[1] == ':' and normalizedPath[2] == '/':
    let drive = normalizedPath[0 .. 1]
    var encodedSegments: seq[string]
    for segment in normalizedPath[3 .. ^1].split('/'):
      if segment.len > 0:
        encodedSegments.add(encodeUrl(segment, usePlus = false))
    return "file:///" & drive & "/" & encodedSegments.join("/")

  var encodedSegments: seq[string]
  for segment in normalizedPath.split('/'):
    if segment.len > 0:
      encodedSegments.add(encodeUrl(segment, usePlus = false))
  encodedSegments.join("/")

proc addSarifResult(results: var JsonNode, ruleId, level, message, filePath: string) =
  let ruleIndex = sarifRuleIndex(ruleId)
  results.add(%*{
    "ruleId": ruleId,
    "ruleIndex": ruleIndex,
    "level": level,
    "message": {"text": message},
    "locations": [{
      "physicalLocation": {
        "artifactLocation": {"uri": sarifUri(filePath)}
      }
    }]
  })

proc sarifDocument(results: JsonNode): JsonNode =
  result = %*{
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
      "tool": {
        "driver": {
          "name": "Project Chimera",
          "version": "0.1.0",
          "rules": [
            {
              "id": SarifRuleIds[0],
              "name": "InvalidPortableExecutable",
              "shortDescription": {"text": "The input could not be parsed as a valid PE file."}
            },
            {
              "id": SarifRuleIds[1],
              "name": "AnalysisFailure",
              "shortDescription": {"text": "The optional analysis stage failed."}
            },
            {
              "id": SarifRuleIds[2],
              "name": "HighSectionEntropy",
              "shortDescription": {"text": "A PE section has unusually high entropy."}
            },
            {
              "id": SarifRuleIds[3],
              "name": "SuspiciousImport",
              "shortDescription": {"text": "The PE imports an API commonly relevant to suspicious behavior."}
            },
            {
              "id": SarifRuleIds[4],
              "name": "YaraRuleMatch",
              "shortDescription": {"text": "The file matched a user-supplied YARA rule."}
            },
            {
              "id": SarifRuleIds[5],
              "name": "ElevatedHeuristicRisk",
              "shortDescription": {"text": "The heuristic triage score met the configured reporting threshold."}
            },
            {
              "id": SarifRuleIds[6],
              "name": "IOCDetected",
              "shortDescription": {"text": "Hardcoded indicators of compromise (IP, URL, PDB path, or sensitive string) found in the PE."}
            }
          ]
        }
      },
      "results": results
    }]
  }

proc addAnalysisSarif(results: var JsonNode, record: JsonNode) =
  let filePath = record["file_path"].getStr()
  if record["status"].getStr() == "error":
    addSarifResult(results, SarifRuleIds[0], "error",
      record["error"].getStr(), filePath)
    return
  if record["status"].getStr() == "analysis_error":
    addSarifResult(results, SarifRuleIds[1], "error",
      record["error"].getStr(), filePath)
    return

  for section in record["sections"]:
    let entropy = section["entropy"].getFloat()
    if entropy >= 7.2:
      let sectionName = section["name"].getStr()
      addSarifResult(results, SarifRuleIds[2], "warning",
        fmt"Section {sectionName} has entropy {entropy:.3f}.", filePath)

  const suspiciousImports = [
    "createremotethread", "internetopenurla", "internetopenurlw",
    "setwindowshookexa", "setwindowshookexw", "virtualalloc",
    "writeprocessmemory"
  ]
  for imported in record["imports"]:
    let importName = imported.getStr()
    if importName.toLowerAscii() in suspiciousImports:
      addSarifResult(results, SarifRuleIds[3], "warning",
        "The file imports " & importName & ".", filePath)

  if record.hasKey("analysis"):
    let analysis = record["analysis"]
    let riskScore = analysis["risk_score"].getFloat()
    if riskScore >= 0.5:
      addSarifResult(results, SarifRuleIds[5], "warning",
        fmt"Heuristic risk score {riskScore:.3f} is at least 0.500.", filePath)
    for match in analysis["yara_matches"]:
      addSarifResult(results, SarifRuleIds[4], "warning",
        "Matched YARA rule " & match["rule"].getStr() &
          " in namespace " & match["namespace"].getStr() & ".",
        filePath)

    if record.hasKey("iocs"):
      let iocs = record["iocs"]
      for ioc in iocs:
        let iocStr = ioc.getStr()
        addSarifResult(results, SarifRuleIds[6], "warning",
          "Hardcoded IOC detected: " & iocStr, filePath)

proc analyzeSingle(filePath: string, rulesPath: string, cacheDbPath: string,
                   usePython: bool, noCache: bool): JsonNode =
  let record = parseJson(parseRecord(filePath))
  if record["status"].getStr() == "error":
    return record
  if not usePython or noCache:
    return record
  let featureJson = $(%*{
    "schema_version": record["schema_version"],
    "file_path": record["file_path"],
    "architecture": record["architecture"],
    "content_hash": record["content_hash"],
    "sections": record["sections"],
    "imports": record["imports"]
  })
  try:
    record["analysis"] = analyzeWithPython(featureJson, rulesPath, cacheDbPath)
  except CatchableError as error:
    record["status"] = %"analysis_error"
    record["error"] = %error.msg
  return record

proc runDaemon(options: CliOptions) =
  var pythonInitError = ""
  if options.usePython:
    try:
      initPythonBridge()
    except CatchableError as error:
      pythonInitError = error.msg
      stderr.writeLine("[DAEMON] Python init failed: " & error.msg)

  let cacheDbPath = if options.usePython and not options.noCache:
      getAppDir() / "chimera_cache.sqlite3"
    else:
      ""

  while true:
    let reqLine = readLine(stdin)
    if reqLine.len == 0:
      break
    if reqLine.strip().len == 0:
      continue

    var filePath = ""
    var rulesPath = options.rulesPath
    var noCache = options.noCache
    try:
      let req = parseJson(reqLine)
      if req.hasKey("file_path"):
        filePath = req["file_path"].getStr()
      if req.hasKey("rules_path"):
        rulesPath = req["rules_path"].getStr()
      if req.hasKey("no_cache"):
        noCache = req["no_cache"].getBool()
    except CatchableError:
      echo %*{"error": "Invalid JSON request", "raw": reqLine}
      flushFile(stdout)
      continue

    if filePath.len == 0:
      echo %*{"error": "file_path is required"}
      flushFile(stdout)
      continue

    try:
      let result = analyzeSingle(filePath, rulesPath, cacheDbPath,
                                 options.usePython, noCache)
      if pythonInitError.len > 0 and options.usePython:
        result["status"] = %"analysis_error"
        result["error"] = %pythonInitError
      echo $result
    except CatchableError as error:
      echo %*{"file_path": filePath, "status": "error", "error": error.msg}
    flushFile(stdout)

proc analyzePaths(paths: seq[string], options: CliOptions): int =
  var pythonInitError = ""
  if options.usePython:
    try:
      initPythonBridge()
    except CatchableError as error:
      pythonInitError = error.msg

  let cacheDbPath = if options.usePython and not options.noCache:
      getAppDir() / "chimera_cache.sqlite3"
    else:
      ""

  let workers = max(1, min(cpuinfo.countProcessors(), paths.len))
  var records = newJArray()
  var sarifResults = newJArray()
  var reportRecords = newJArray()
  var taskPool = Taskpool.new(num_threads = workers)
  defer: taskPool.shutdown()

  for startIndex in countup(0, paths.high, workers):
    let batchEnd = min(startIndex + workers, paths.len)
    var futures: seq[Flowvar[string]]
    for index in startIndex ..< batchEnd:
      futures.add(taskPool.spawn(parseRecord(paths[index])))

    for futureIndex in 0 ..< futures.len:
      let record = parseJson(sync(move(futures[futureIndex])))
      if record["status"].getStr() == "error":
        inc result
      elif options.usePython:
        if pythonInitError.len > 0:
          record["status"] = %"analysis_error"
          record["error"] = %pythonInitError
          inc result
        else:
          let featureJson = $(%*{
            "schema_version": record["schema_version"],
            "file_path": record["file_path"],
            "architecture": record["architecture"],
            "content_hash": record["content_hash"],
            "sections": record["sections"],
            "imports": record["imports"]
          })
          try:
            record["analysis"] = analyzeWithPython(featureJson, options.rulesPath, cacheDbPath)
          except CatchableError as error:
            record["status"] = %"analysis_error"
            record["error"] = %error.msg
            inc result

      if options.outputSarif:
        addAnalysisSarif(sarifResults, record)
      elif options.outputJson:
        records.add(record)
      else:
        formatHuman(record)

      if record.hasKey("analysis"):
        reportRecords.add(record)

  if options.outputSarif:
    echo $sarifDocument(sarifResults)
  if options.outputJson:
    echo $(%*{"schema_version": 1, "results": records})

  if options.reportPath.len > 0:
    if not options.usePython:
      raise newException(ValueError, "--report requires Python analysis (do not use --no-ai)")
    let reportResults = newJArray()
    for rec in reportRecords:
      reportResults.add(rec)
    let reportWrapper = %*{"schema_version": 1, "results": reportResults}
    let reportJson = $reportWrapper
    let reportText = generateReport(reportJson, options.reportFormat)
    let rptFmt = options.reportFormat
    var f = newFileStream(options.reportPath, fmWrite)
    f.write(reportText)
    f.close()
    echo "[REPORT] Written to " & options.reportPath & " (" & rptFmt & ")"

proc parseArguments(): CliOptions =
  result.usePython = true
  result.reportFormat = "markdown"
  var index = 1
  while index <= paramCount():
    let argument = paramStr(index)
    case argument
    of "--help", "-h":
      printUsage()
      quit(0)
    of "--json":
      result.outputJson = true
    of "--sarif":
      result.outputSarif = true
    of "--no-ai":
      result.usePython = false
    of "--no-cache":
      result.noCache = true
    of "--daemon":
      result.daemon = true
    of "--gui":
      result.gui = true
    of "--list-processes":
      result.showProcesses = true
    of "--dir":
      inc index
      if index > paramCount():
        raise newException(ValueError, "--dir requires a directory path")
      result.directoryPath = paramStr(index)
    of "--rules":
      inc index
      if index > paramCount():
        raise newException(ValueError, "--rules requires a YARA rules path")
      result.rulesPath = paramStr(index)
    of "--report":
      inc index
      if index > paramCount():
        raise newException(ValueError, "--report requires an output path")
      result.reportPath = paramStr(index)
    of "--report-format":
      inc index
      if index > paramCount():
        raise newException(ValueError, "--report-format requires markdown or html")
      result.reportFormat = paramStr(index)
    else:
      if argument.startsWith("-"):
        raise newException(ValueError, "Unknown option: " & argument)
      if result.targetPath.len > 0:
        raise newException(ValueError, "Only one input file may be analyzed at a time")
      result.targetPath = argument
    inc index

  if result.rulesPath.len > 0 and not result.usePython:
    raise newException(ValueError, "--rules cannot be combined with --no-ai")
  if result.outputSarif and result.outputJson:
    raise newException(ValueError, "--sarif cannot be combined with --json")
  if result.reportPath.len > 0 and not result.usePython:
    raise newException(ValueError, "--report cannot be combined with --no-ai")
  if result.reportFormat notin ["markdown", "html"]:
    raise newException(ValueError, "--report-format must be 'markdown' or 'html'")
  if result.showProcesses:
    if result.targetPath.len > 0 or result.directoryPath.len > 0 or
        result.rulesPath.len > 0 or result.outputJson or result.outputSarif or
        not result.usePython or result.noCache or result.gui or result.daemon:
      raise newException(ValueError, "--list-processes cannot be combined with other options")
    return
  if result.gui:
    if result.daemon or result.outputJson or result.outputSarif or
        result.reportPath.len > 0 or result.directoryPath.len > 0:
      raise newException(ValueError,
        "--gui cannot be combined with --daemon, --dir, --json, --sarif, or --report")
    if not result.usePython:
      raise newException(ValueError, "--gui requires Python analysis (do not use --no-ai)")
    return
  if result.directoryPath.len > 0 and result.targetPath.len > 0:
    raise newException(ValueError, "--dir cannot be combined with a file path")
  if not result.daemon and result.directoryPath.len == 0 and result.targetPath.len == 0:
    raise newException(ValueError, "A PE file path or --dir is required")

proc pythonInterpreter(appDir: string): string =
  let bundled = appDir / "python_runtime" / "python.exe"
  if fileExists(bundled):
    return bundled
  "python"

const DashboardPort = 8765

proc dashboardRunning(): bool =
  try:
    let socket = newSocket()
    defer: socket.close()
    socket.connect("127.0.0.1", Port(DashboardPort), timeout = 400)
    return true
  except CatchableError:
    return false

proc launchDashboard(cli: CliOptions): int =
  let appDir = getAppDir()
  let dashboardUrl = "http://127.0.0.1:" & $DashboardPort & "/"
  if dashboardRunning():
    echo "[GUI] A dashboard is already running at " & dashboardUrl
    echo "[GUI] Drop files onto it or reuse its path field to scan more samples."
    return 0

  let script = appDir / "python_core" / "dashboard.py"
  if not fileExists(script):
    stderr.writeLine("[ERROR] Dashboard entry point not found: " & script)
    return 1

  var arguments = @[script, "--port", $DashboardPort]
  if cli.rulesPath.len > 0:
    arguments.add("--rules")
    arguments.add(cli.rulesPath)
  if cli.targetPath.len > 0:
    arguments.add("--open")
    arguments.add(cli.targetPath)

  let interpreter = pythonInterpreter(appDir)
  try:
    # poDaemon detaches the child (DETACHED_PROCESS) so this process can exit
    # immediately instead of waiting on the dashboard's console handles.
    discard startProcess(interpreter, workingDir = appDir, args = arguments,
                         options = {poUsePath, poDaemon})
  except OSError as error:
    stderr.writeLine("[ERROR] Could not start the dashboard via '" & interpreter &
      "': " & error.msg)
    stderr.writeLine("        Install Python 3 or place a bundled runtime in python_runtime\\.")
    return 1

  echo "[GUI] Chimera-Vision dashboard starting at " & dashboardUrl
  echo "[GUI] If the browser does not open, visit that URL manually."
  return 0

proc main() =
  let options = parseArguments()
  if options.showProcesses:
    listProcesses()
    return
  if options.daemon:
    runDaemon(options)
    return
  if options.gui:
    quit(launchDashboard(options))

  let paths = if options.directoryPath.len > 0:
      collectPeFiles(options.directoryPath)
    else:
      @[options.targetPath]
  if analyzePaths(paths, options) > 0:
    quit(1)

when isMainModule:
  try:
    main()
  except CatchableError as error:
    stderr.writeLine("[ERROR] " & error.msg)
    quit(1)
