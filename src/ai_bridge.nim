import nimpy
import nimpy/py_lib as pyRuntime
import std/[json, os, strformat, strutils]

var
  pythonInitialized = false
  modelModule: PyObject = nil

proc loadBundledRuntime(runtimeDir: string): bool =
  if not dirExists(runtimeDir):
    return false

  for kind, path in walkDir(runtimeDir):
    if kind == pcFile and path.extractFilename.toLowerAscii.startsWith("python") and
        path.toLowerAscii.endsWith(".dll"):
      putEnv("PATH", runtimeDir & PathSep & getEnv("PATH"))
      putEnv("PYTHONHOME", runtimeDir)
      pyRuntime.pyInitLibPath(path)
      return true
  false

proc initPythonBridge*() =
  if pythonInitialized:
    return

  let runtimeDir = getAppDir() / "python_runtime"
  discard loadBundledRuntime(runtimeDir)

  let appDir = getAppDir()
  if not dirExists(appDir / "python_core"):
    raise newException(IOError, "Python inference directory not found: " & appDir / "python_core")

  let pythonSys = pyImport("sys")
  discard pythonSys.path.insert(0, appDir)
  modelModule = pyImport("python_core.model_inference")
  pythonInitialized = true

proc analyzeWithPython*(featureJson, rulesPath, cacheDbPath: string): JsonNode =
  if not pythonInitialized:
    raise newException(ValueError, "Python bridge has not been initialized")

  let pyResult = modelModule.analyze_feature_json(featureJson, rulesPath, cacheDbPath, cacheDbPath).to(string)
  result = parseJson(pyResult)
  if not result.hasKey("risk_score") or result["risk_score"].kind != JFloat:
    raise newException(ValueError, "Python analysis returned an invalid risk score")
  let score = result["risk_score"].getFloat()
  if score != score or score < 0.0 or score > 1.0:
    raise newException(ValueError, fmt"Python analysis returned an invalid risk score: {score}")
  if not result.hasKey("yara_matches") or result["yara_matches"].kind != JArray:
    raise newException(ValueError, "Python analysis returned invalid YARA matches")

proc generateReport*(recordsJson, reportFormat: string): string =
  if not pythonInitialized:
    raise newException(ValueError, "Python bridge has not been initialized")
  let pyResult = modelModule.generate_report(recordsJson, reportFormat).to(string)
  result = pyResult
