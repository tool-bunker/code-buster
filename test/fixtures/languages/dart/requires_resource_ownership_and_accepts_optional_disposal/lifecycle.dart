class LifecycleState {
  AnimationController? _controller;
  ReceivePort? receiver;

  void initState() {
    _controller = AnimationController();
  }

  void dispose() {
    _controller?.dispose();
  }
}
