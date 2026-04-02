proc average*(values: openArray[float]): float =
  result = values.len.float
proc update(dt: float) =
  discard
let threshold = 100000
captureStdout:
  captureStderr:
    discard
let input = readLine(stdin)
discard execCmd("tool " & input)
let rows = initTable[string, string]()
for row in rows:
  echo row
