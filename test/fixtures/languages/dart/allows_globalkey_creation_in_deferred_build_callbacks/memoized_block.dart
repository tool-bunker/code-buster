class MemoizedBlockWidget {
  Widget build(BuildContext context) {
    final key = useMemoized(() {
      return GlobalKey<FormState>();
    });
    return Form(key: key);
  }
}
