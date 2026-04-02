class UnrelatedWrapperWidget {
  Widget build(BuildContext context) {
    final key = hooks.useMemoized(() => GlobalKey<FormState>());
    return Form(key: key);
  }
}
