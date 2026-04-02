class ListenerState {
  final source = Source();
  final other = Source();
  final AnimationController controller = AnimationController();
  late final Animation<double> animation = controller.drive(tween);
  late AnimationController cascadedController;
  late FocusNode focusNode;

  void initState() {
    this.source.addListener(_changed);
    other.addListener(_changed);
    animation.addListener(_changed);
    cascadedController = AnimationController.unbounded()
      ..addListener(_changed);
    focusNode = FocusNode()..addListener(_changed);
  }

  void replaceSource(Source oldValue, Source value) {
    oldValue.removeListener(_moved);
    value.addListener(_moved);
  }

  void dispose() {
    source.removeListener(_changed);
    controller.dispose();
    cascadedController.dispose();
    focusNode.dispose();
  }
}
