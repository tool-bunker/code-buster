package service
func Run() {
  for item := range items {
    defer item.Close()
  }
}
