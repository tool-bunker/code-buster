class DirectWidget {
  Widget build(BuildContext context) {
    final key = GlobalKey<FormState>();
    return Form(key: key);
  }
}
