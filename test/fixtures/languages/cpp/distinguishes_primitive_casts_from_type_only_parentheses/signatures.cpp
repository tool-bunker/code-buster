static std::true_type Probe(int);
void operator()(int) & {}
using Callback = std::function<void(int)>;
int bytes = sizeof(int) * 2;
int converted = (int)value;
