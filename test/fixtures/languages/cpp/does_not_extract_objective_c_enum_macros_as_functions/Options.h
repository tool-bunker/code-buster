typedef NS_OPTIONS(NSUInteger, LoadOptions) {
  LoadOptionRetry = 1 << 0,
  LoadOptionProgressive = 1 << 1,
};

typedef NS_ENUM(NSInteger, LoadState) {
  LoadStateIdle,
  LoadStateFinished,
};

int actualFunction(void) {
  return 0;
}
