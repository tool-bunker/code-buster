class Model {
  const Model({
    required this.id,
    required this.name,
    required this.email,
    required this.status,
    required this.primaryColorIndex,
  });

  final int id;
  final String name;
  final String email;
  final String status;
  final int primaryColorIndex;
  static const Model empty = Model(
    id: 0,
    name: '',
    email: '',
    status: '',
    primaryColorIndex: 0,
  );

  Model copyWith({String? name, int? primaryIndex}) => Model(
    id: id,
    name: name ?? this.name,
    email: this.email,
    status: status,
    primaryColorIndex: primaryIndex ?? primaryColorIndex,
  );
}
