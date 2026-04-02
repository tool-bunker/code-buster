Future<void> topLevel(bool enabled) async {
  if (enabled) print('yes');
}
class Worker {
  Worker.named() { print('created'); }
  void run() {
    while (ready) {
      work();
    }
  }
  void abstractMethod();
}
