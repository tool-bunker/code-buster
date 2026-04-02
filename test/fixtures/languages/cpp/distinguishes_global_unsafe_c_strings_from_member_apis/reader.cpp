void read(char* buffer, Stream& stream, Stream* pointer) {
  gets(buffer);
  strcpy(buffer, "value");
  QString text;
  text.sprintf("%s", "value");
  pointer->sprintf(buffer, 64);
  ::sprintf(buffer, "%s", "value");
  std::sprintf(buffer, "%s", "value");
  sprintf(buffer, "%s", "value");
  stream.gets(buffer, 64);
  pointer -> gets(buffer, 64);
}
char* IOFile::gets(char* buffer, int size) { return buffer; }
char* gets(char* buffer, int size);
