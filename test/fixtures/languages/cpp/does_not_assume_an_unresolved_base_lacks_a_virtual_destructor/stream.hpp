class StreamBuffer : public std::streambuf {
 protected:
  virtual int overflow(int value) override;
};
