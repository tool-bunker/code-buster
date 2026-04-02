class Comparisons {
  boolean quoted(char quote) {
    return quote == '\'' || quote == '"';
  }
  String answer(int result) {
    return result == 0 ? "yes" : "no";
  }
  boolean same(String value) {
    return value == "expected";
  }
}
