using System.Runtime.Serialization.Formatters.Binary;
class LegacyData {
  /*
  var oldFormatter = new BinaryFormatter();
  */
  void Inspect() {
    var typeName = "BinaryFormatter";
    Consume(); // BinaryFormatter is unavailable on this target.
  }
}
