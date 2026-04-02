proc update(position: Vec2) =
  if position.x == 0.0: discard
  if distance(position, target) == 0: discard
  let value = rand(10)
  let clock = getTime()
  playSound(hit)
  saveState(game)
  for entity in entities:
    entities.remove(entity)
proc draw() =
  beginScissor()
  if keyPressed(Escape): discard
  drawText($"score")
