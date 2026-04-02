#include "widget.hpp"
using namespace std;
int main() {
  Widget* widget = new Widget();
  free(widget);
  goto done;
done:
  return 0;
}
