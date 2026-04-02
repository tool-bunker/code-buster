#include <cstdlib>
int main() {
  void* value = malloc(4);
  free(value);
  return 0;
}
