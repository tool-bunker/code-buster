void Visit(void (*callback)(void*), void* state);
void Ignore(void*) {}
int PointerSize() { return sizeof(void*); }
float Scale(int value) { return (float)value; }
