class Cache {
  int _valueFromJson(Map<String, Object?> json) => json['value'] as int;

  int? decode(Map<String, Object?> json) {
    try {
      return _valueFromJson(json);
    } on Object {
      return null;
    }
  }
}
