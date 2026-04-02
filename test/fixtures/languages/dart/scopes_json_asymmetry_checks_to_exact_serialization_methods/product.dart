class Product {
  Product(this.id);
  final String id;

  factory Product.fromJson(Map<String, dynamic> json) =>
      Product(json['id'] as String);

  static String _toJsonString(Object? value) => '$value';

  static const Map<String, String> colors = <String, String>{
    'red': '#ff0000',
  };
}
