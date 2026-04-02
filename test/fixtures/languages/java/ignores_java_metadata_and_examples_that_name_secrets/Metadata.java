class Metadata {
  // Input: secret = "1807";
  /* Input: password = "1123"; */
  static final String KEY_TOKEN = "token";
  void criteria(String value, int i) {
    addCriterion("password =", value, "password");
    String token = "token::" + (i % 3 + 1);
    String password = "s3cr3t";
  }
}
