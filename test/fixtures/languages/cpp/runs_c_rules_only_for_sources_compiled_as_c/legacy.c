#include "legacy.h"
#include "../shared/api.h"
void release(void *value) {
  free(value);
}
