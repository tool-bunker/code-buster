class Conditions {
  bool Match(bool left, bool right, int errorCode, Modifiers modifiers) {
    if (left & right) return true;
    if ((0xFFFF0000 & errorCode) != 0) return false;
    if ((modifiers & Modifiers.Control) == Modifiers.Control) return false;
    while (left | right) return false;
    return false;
  }
}
