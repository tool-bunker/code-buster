const collect = async () => {
  try {
    for (const group of groups) {
      for (const item of group) {
        consume(item);
      }
    }
  } finally {
    cleanup();
  }
}
const publish = async () => {
  await publishResults();
  for (const batch of batches) {
    if (batch.ready) {
      for (const item of batch.items) {
        await process(item);
      }
    }
  }
}
