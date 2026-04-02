class Adapter {
  async read(): Promise<void> {
    for (const group of groups) {
      for (const item of group) {
        await consume(item);
      }
    }
  }

  async write(): Promise<void> {
    await publishResults();
  }
}
