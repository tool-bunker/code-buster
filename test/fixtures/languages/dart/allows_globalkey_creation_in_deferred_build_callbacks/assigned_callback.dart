class AssignedCallbackWidget {
  Widget build(BuildContext context) {
    final openDialog = () => Dialog(
      formKey: GlobalKey<FormState>(),
    ).show(context);
    return Button(onTap: openDialog);
  }
}
