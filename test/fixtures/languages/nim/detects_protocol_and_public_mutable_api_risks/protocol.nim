type Client* = ref object
  headers*: seq[string]
proc upgrade(connectionHeader: string) =
  if connectionHeader.contains("Upgrade"):
    discard
  for token in connectionHeader.split(","):
    discard
# websocket handshake
