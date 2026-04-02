- (void)handlePress:(id)press
    callback:(id)callback API_AVAILABLE(ios(13.4)) {
  if (press) { callback(); }
}
