proc render*(tensor: Tensor, shape: Shape) =
  for item in tensor:
    let buffer = newSeq[int](item.len)
    result &= readFile(item.path)
    entities.add(item)
    let texture = loadTexture(item.path)
    let offset = rand(10)
proc first(x: int, y: int, width: int, height: int) = discard
proc second(x: int, y: int, width: int, height: int) = discard
proc third(x: int, y: int, width: int, height: int) = discard
