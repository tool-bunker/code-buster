enum Mode { ready }

class Contract {
  Contract(this.id, this.name);
  final int id;
  final String name;
  late final String token;
  Mode mode = Mode.ready;

  Contract copyWith({int? id}) => Contract(id ?? this.id, name);

  factory Contract.fromJson(Map<String, dynamic> json) =>
      Contract(json['id'] as int, json['name'] as String);

  Map<String, dynamic> expose() => <String, dynamic>{'id': id};

  Map<String, Object?> toJson() => <String, Object?>{
    'id': id,
    'name': name,
    'token': token,
    'mode': mode.name,
  };

Widget build(BuildContext context, Ref ref) => Container(child: Expanded(
  child: Image.network(
    'https://example.test/image.png',
    frameBuilder: frame,
  ),
));

Widget action(Ref ref) => GestureDetector(
  onTap: () {
    ref.watch(selectionProvider);
  },
);

void retain(List<String> blocked, List<String> values) {
  for (final value in values) {
    if (blocked.contains(value)) continue;
  }
}
}
