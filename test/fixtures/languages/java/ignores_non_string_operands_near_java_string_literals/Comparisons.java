class Comparisons {
  // value == "comment example"
  @Cacheable(unless = "#result.status == 'DOWN'")
  boolean compare(String value, String tempName, HairType hairType, int length) {
    if (tempName == null || "unknown".equalsIgnoreCase(tempName)) {
      return false;
    }
    if (hairType != HairType.BALD || length == Integer.MAX_VALUE) {
      return value == "expected";
    }
    return compareFiles() == 0 ? "same" : "different";
  }
  String map(Object item) {
    return item != null ? requireNonNull(item, "message") : null;
  }
}
