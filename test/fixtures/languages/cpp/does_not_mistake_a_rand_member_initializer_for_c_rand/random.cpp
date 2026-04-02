struct State {
  State(int seed) : rand(seed) {}
  Random rand;
};
int value = std::rand();
void Seed() { std::srand(0); }
