namespace Demo {
using System.Text;
class Resource {
  void Read() {
    using (var stream = Open()) {
      Consume(stream);
    }
    using var other = Open();
  }
}
}
