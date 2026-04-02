class Files {
  void leaking() {
    FileInputStream input = new FileInputStream(path);
    consume(input);
  }
  void safe() {
    FileInputStream input = new FileInputStream(path);
    input.close();
  }
  FileOutputStream transferred() {
    FileOutputStream output = new FileOutputStream(path);
    return output;
  }
  void inMemory(String value) {
    BufferedReader reader = new BufferedReader(new StringReader(value));
    reader.lines().forEach(this::consume);
  }
}
