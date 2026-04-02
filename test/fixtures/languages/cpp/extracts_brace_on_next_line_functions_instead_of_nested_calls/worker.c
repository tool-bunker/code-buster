static int process(struct item *item)
{
  if (curl_strnequal(item->name, "one", 3) ||
      curl_strnequal(item->name, "two", 3)) {
    return 1;
  }
  list_for_each_entry(item, &items) {
    consume(item);
  }
  HASH_ITER(hash, items, item, next) {
    release(item);
  }
  return 0;
}
