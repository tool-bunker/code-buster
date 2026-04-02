class Contract {
  Contract(this.id, this.name);
  final int id;
  final String name;
  late final String token;
  String modeValue = 'ready';

  Contract copyWith({
    int? id,
    String? name,
    String? token,
    String? modeValue,
  }) {
    final model = Contract(id ?? this.id, name ?? this.name);
    model.token = token ?? this.token;
    model.modeValue = modeValue ?? this.modeValue;
    return model;
  }

  factory Contract.fromJson(Map<String, Object?> json) {
    final model = Contract(json['id'] as int, json['name'] as String);
    model.token = json['token'] as String;
    return model;
  }

  Map<String, Object?> expose() => <String, Object?>{'id': id};

  Map<String, dynamic> toJson() => <String, dynamic>{
    'id': id,
    'name': name,
    'token': token,
    'mode': modeValue,
  };

Widget build(BuildContext context) => Column(children: [
  Expanded(
    child: Image.network(
      'https://example.test/image.png',
      errorBuilder: imageError,
    ),
  ),
]);

Widget action(Ref ref) => GestureDetector(
  onTap: () {
    ref.read(selectionProvider);
  },
);

void retain(Set<String> blocked, List<String> values) {
  for (final value in values) {
    if (blocked.contains(value)) continue;
  }
}
}
