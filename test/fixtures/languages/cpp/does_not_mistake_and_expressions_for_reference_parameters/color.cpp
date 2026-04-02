int Blend(int color) {
  int red = Convert((int)(color >> 8) & 0xFF);
  return red;
}
bool InRange(int value) {
  return value > 0 && value < 10;
}
template <typename G>
void Forward(G&& value) {}
void Convert(float& output) {
  output = 1.0f;
}
void Observe(EventArgs const& event) {}
