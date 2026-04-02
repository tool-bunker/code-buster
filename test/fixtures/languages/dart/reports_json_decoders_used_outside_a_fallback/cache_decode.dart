class Cache {
  int _valueFromJson(Map<String, Object?> json) => json['value'] as int;
  int decode(Map<String, Object?> json) => _valueFromJson(json);
}
