type
  Left* = ref object
    right*: Right

proc boundary() = discard

type
  Right* = ref object
    left*: Left

let threshold = 100000
