import "service" for Service
class Main {
  run() {
    while (true) {
      System.print("tick")
    }
    var value = Num.fromString("bad")
    Fiber.abort("stop")
  }
}
