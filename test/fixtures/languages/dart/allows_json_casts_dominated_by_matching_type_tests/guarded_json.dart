Object? read(Map<String, dynamic> json) {
  if (json['name'] is String) {
    return json['name'] as String;
  }
  final items = json['items'] is List
      ? json['items'] as List<dynamic>
      : <dynamic>[];
  return items;
}
