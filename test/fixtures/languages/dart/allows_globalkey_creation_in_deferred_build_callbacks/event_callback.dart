class EventCallbackWidget {
  Widget build(BuildContext context) {
    return Button(
      onTap: () => Dialog(
        formKey: GlobalKey<FormState>(),
      ).show(context),
    );
  }
}
