#define BRIDGE_BUFFER_SIZE 4096
void releaseBridge(void *value) {
  free(value);
}
