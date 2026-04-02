func run() {
  defer cleanup()
  for item := range items {
    defer item.Close()
  }
}
