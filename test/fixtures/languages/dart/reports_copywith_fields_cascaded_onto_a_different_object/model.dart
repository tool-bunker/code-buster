class Holder {
  int recursion = 0;
}

class Model {
  int count = 0;
  int recursion = 0;
  final Holder other = Holder();

  Model copyWith({int? count}) {
    other..recursion = recursion;
    return Model()..count = count ?? this.count;
  }
}
