class EditorState {
  late final Object service = Object();
  late final Object controller = Object();
  late final Object session = Object();
  late final Object documents = Object();
  late final Object viewModel = Object();
  late final Object game = Object();

  Object decode() => ProjectCodec.fromJsonFiles(defaultDocuments());
  Object encode(Item item) => item.toJson();
}

class PersistedContract {
  PersistedContract(this.id);
  final int id;
  late final String token;

  factory PersistedContract.fromJson(Map<String, Object?> json) =>
      PersistedContract(json['id'] as int);

  Map<String, Object?> toJson() => {'id': id, 'token': token};
}

class ContractWithRuntimeService {
  ContractWithRuntimeService(this.id);
  final int id;
  late final Object service = Object();

  factory ContractWithRuntimeService.fromJson(Map<String, Object?> json) =>
      ContractWithRuntimeService(json['id'] as int);

  Map<String, Object?> toJson() => {'id': id};
}
