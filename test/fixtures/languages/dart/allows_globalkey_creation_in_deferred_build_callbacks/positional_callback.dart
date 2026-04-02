class PositionalCallbackWidget {
  Widget build(BuildContext context) {
    return CallbackHost(
      () => Form(key: GlobalKey<FormState>()),
    );
  }
}
