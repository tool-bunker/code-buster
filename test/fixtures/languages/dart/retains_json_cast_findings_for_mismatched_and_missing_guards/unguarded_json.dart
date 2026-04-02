Object read(Map<String, dynamic> json) {
  if (json['name'] is int) {
    return json['other'] as int;
  }
  if (json['count'] is String) {
    return json['count'] as int;
  }
  return json['raw'] as String;
}
