class Handlers {
  private async void Window_Load(object sender, EventArgs e) {}
  private async void Button_Click(object? sender, Ui.ClickEventArgs e) {}
  protected override async void OnClosing(WindowClosingEventArgs e) {}
  private async void Refresh() {}
  private async void NotAHandler(string sender, EventArgs e) {}
  // An async void method should only appear as an event handler.
  #pragma warning disable VSTHRD100 // Avoid async void methods
}
