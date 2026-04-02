let symbol = cast[PluginProc](symAddr(lib, "run"))
let lib = loadLib(path)
let pluginCallbacks: seq[proc ()] = @[]
pluginContext["default"] = value
proc one*(value: JsonNode) = discard
proc two*(value: JsonValue) = discard
proc three*(value: Value) = discard
