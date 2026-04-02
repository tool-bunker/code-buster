using System.Runtime.Remoting;
class LegacyService : MarshalByRefObject {
  /*
  CoCreateInstance(CLSID_Legacy);
  [ComImport]
  */
  [ComImport]
  interface INative {}

  void Wrap(object value) {
    var typeName = "System.Runtime.Remoting.Services";
    var url = "https://example.test/CoCreateInstance";
    Consume(value); // RemotingConfiguration and MarshalByRefObject
    CoCreateInstance();
  }
}
