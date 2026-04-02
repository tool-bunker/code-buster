try {
  if (input != null) {
    JSON.parse(input);
  }
} catch (error) {
  report(error);
}
try {
  JSON.parse(input);
} finally {
  cleanup();
  JSON.parse(cleanupPayload);
}
try {
  decode();
} catch (error) {
  JSON.parse(fallback);
}
JSON.parse(input);
