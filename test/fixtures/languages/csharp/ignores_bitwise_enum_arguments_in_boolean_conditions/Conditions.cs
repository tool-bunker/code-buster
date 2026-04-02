class Conditions {
  bool Parse(string value) {
    if (TryParse(value, NumberStyles.Float | NumberStyles.AllowThousands)) return true;
    if (ready & enabled) return true;
    return false;
  }
}
