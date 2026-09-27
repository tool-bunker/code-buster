class Gesture {
  (int, int)? _start;
  bool _cancelled = false;

  bool get active => _start != null && !_cancelled;

  int preview() {
    if (!active) return 0;
    return _start!.$1;
  }

  int unsafePreview() => _start!.$1;
}

String guardedBranch(String? item, bool erase) {
  if (item == null && !erase) return 'none';
  final behavior = erase ? 'erase' : item!.toUpperCase();
  if (behavior == 'paint' && !erase) return item!;
  return behavior;
}

void immediateGuard(Holder holder) {
  if (holder.value != null) consume(holder.value!);
}

String incompleteGuard(String? value, bool enabled) {
  if (value == null && enabled) return 'none';
  return value!;
}

String invalidatedGuard(String? value) {
  if (value == null) return 'none';
  value = null;
  return value!;
}
