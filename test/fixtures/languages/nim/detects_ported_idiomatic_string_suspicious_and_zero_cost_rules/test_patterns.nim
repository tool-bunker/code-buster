let answer = 42
let home = getHomeDir().strip()
let values = items.map(convert).filter(valid)
let number = parseInt(readLine(stdin))
let formatted = formatFloat(value).replace('.', ',')
let clean = source.replace("\t", "  ")
let suffix = value.strip(chars="ab")
let enabled = not not ready
skip()
echo "<item>", value
type UserId* = distinct int
proc dumpHook(output: var string, value: UserId) =
  output = $value
type Label* = distinct string
proc encodeHook(output: var string, value: Label) =
  output.add($value)
proc consume(data: ptr byte, size: int) = discard
template scoped*(body: untyped) =
  app.active = true
  body
  app.active = false
proc average*(values: openArray[float]): float =
  result = values[0] / values.len
doAssert average(@[0.1]) == 0.1
