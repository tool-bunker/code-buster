class SearchHistory {
  SearchHistory(this.name);
  final String name;
}

class SearchHistoryList {
  Map<String, Object?> toJson(SearchHistory value) =>
      <String, Object?>{'name': value.name};
}
