class MemoizedWidget {
  Widget build(BuildContext context) {
    final key = useMemoized(() => GlobalKey<FormState>());
    return Form(key: key);
  }
}
