class Results {
  void Read(dynamic task, dynamic instruction, dynamic liftable) {
    Consume(task.Result);
    task.Wait();
    task.GetAwaiter().GetResult();
    _readyEvent.Wait();
    Consume(instruction.ResultType);
    Consume(liftable.UnderlyingResultType);
    Consume(task.Resultant);
    task.WaitForExit();
    task.NotGetAwaiter().GetResult();
    task.Result = new object();
    Consume(task.Results);
    // task.Result is intentionally not read here.
  }
}
