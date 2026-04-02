class Model {
  Model(this.id, this.count);

  factory Model.fromJson(Map<String, Object?> json) {
    final reader = Reader(json);
    int requiredInt(String key) => json[key] as int;
    return Model(reader.string('id'), requiredInt('count'));
  }

  final String id;
  final int count;

  Map<String, Object?> toJson() => {'id': id, 'count': count};
}
