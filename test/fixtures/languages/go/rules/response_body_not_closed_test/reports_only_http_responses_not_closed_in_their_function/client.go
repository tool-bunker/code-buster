package client
func leaking() {
  response, err := http.Get(url)
  if err != nil { return }
  consume(response.Body)
}
func safe() {
  response, err := http.Get(url)
  if err != nil { return }
  defer response.Body.Close()
}
