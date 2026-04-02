class DemoState {
  Future<void> load(bool existing) async {
    if (existing) {
      await save();
    } else {
      setState(() {});
    }
    await refresh();
    server.setState((state) => state);
    this.setState(() {});
  }

  Future<void> recover() async {
    try {
      await fetch();
    } catch (_) {
      setState(() {});
    }
  }

  Future<void> guarded() async {
    await fetch();
    if (updated && this.mounted) {
      setState(() {});
    }
  }

  Future<void> guardedByEarlyReturn(Object? result) async {
    await fetch();
    if (result == null || !mounted) {
      return;
    }
    setState(() {});
  }
  Future<void> delegated(bool useDelegate) async {
    if (useDelegate) {
      return await loadFromDelegate();
    }
    setState(() {});
  }
}

Future<void> updateWithCallback(
  void Function(void Function()) setState,
) async {
  await fetch();
  setState(() {});
}
