#if 0
int disabled(void) {
  if (one) {
    if (two) {
      return 1;
    }
  }
}
#else
int active(void) {
#if (0) /* retained reference implementation */
  if (disabled_branch) {
    return 1;
  }
#endif
  return 0;
}
#endif
