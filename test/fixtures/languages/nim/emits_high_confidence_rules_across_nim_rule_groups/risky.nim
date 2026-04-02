import os

proc risky*(a, b, c, d, e, f: int) =
  var value = 1
  try:
    discard
  except:
    discard
  let pointer = cast[pointer](value)
  return value
