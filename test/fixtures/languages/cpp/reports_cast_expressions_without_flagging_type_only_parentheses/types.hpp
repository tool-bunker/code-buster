typedef void (*Callback)(void *);
void remove_state(void *);
void run(void (*func)(void *));
int sizes[sizeof(double)];
int castNumber(double value) {
  return (int)value;
}
void* castPointer(char* value) {
  return (void *)value;
}
