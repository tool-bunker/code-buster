class Cache {
 public:
  virtual ~Cache();
  struct Handle {};
  virtual Handle* Lookup() = 0;
};
