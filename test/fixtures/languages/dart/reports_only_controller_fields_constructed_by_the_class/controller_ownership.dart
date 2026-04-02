class BorrowedControllerState {
  TextEditingController? _controller;

  void attach(TextEditingController controller) {
    _controller = controller;
  }
}

class OwnedControllerState {
  TextEditingController? _controller;

  void initState() {
    _controller = TextEditingController();
  }
}
