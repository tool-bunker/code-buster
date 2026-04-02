class Point(final int x, final int y);

class const Origin(final int x, final int y);

class Counter(final int value) {
  this {
    if (value < 0) {
      throw ArgumentError.value(value);
    }
  }
}
