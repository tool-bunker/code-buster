class RenderContext {
  int listDepth = 0;
  bool ordered = false;
  int recursion = 0;

  RenderContext copyWith({int? listDepth, bool? ordered}) {
    return RenderContext()
      ..listDepth = listDepth ?? this.listDepth
      ..ordered = ordered ?? this.ordered
      ..recursion = recursion;
  }
}
