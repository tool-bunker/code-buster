import os
import std/[a, b, c, d, e, f, g, h, i]

type Public* = object
type Pair* = tuple[x: int, y: int]
type Child* = ref object of RootObj
type UserId* = distinct int

template scoped*(body: untyped) =
  app.active = true
  body
  app.active = false

proc dumpHook(output: var string, value: UserId) =
  output = $value

proc risky*(a, b, c, d, e, f, g: int) =
  var value = 1
  try:
    discard
  except:
    discard
  let pointer = cast[pointer](value)
  return value

proc average*(values: openArray[float]): float =
  result = values[0] / values.len

proc update(dt: float) =
  let input = readLine(stdin)
  discard execCmd("tool " & input)
  player.dead = true
  echo player.position
  let component = getComponent(player)
  velocity += gravity * dt
  drawRect(player.bounds)
  screenWidth = 1920
  entities.add(player)

proc draw() =
  beginScissor()
  camera.x = 10
  if keyPressed(Escape): discard
  drawText($"score")
  drawText("FPS")
  let texture = loadTexture("a")
  let image = loadImage("b")
  let sound = loadSound("c")
  playSound(sound)

proc saveGame() =
  writeFile("save.json", toJson(game))

let rows = initTable[string, string]()
for row in rows:
  echo row
