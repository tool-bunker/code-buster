void configure() {
  connect(this, [this]() {
    if (ready) { start(); }
    if (failed) { stop(); }
  });
}
