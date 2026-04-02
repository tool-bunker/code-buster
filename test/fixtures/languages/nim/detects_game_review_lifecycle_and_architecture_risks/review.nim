proc update(dt: float) =
  player.dead = true
  echo player.position
  let component = getComponent(player)
  for left in entities:
    for right in entities:
      if collide(left, right): discard
  velocity += gravity * dt
  drawRect(player.bounds)
  screenWidth = 1920
proc draw() =
  camera.x = 10
  drawText("FPS")
  let a = loadTexture("a")
  let b = loadImage("b")
  let c = loadSound("c")
proc saveGame() =
  writeFile("save.json", toJson(game))
