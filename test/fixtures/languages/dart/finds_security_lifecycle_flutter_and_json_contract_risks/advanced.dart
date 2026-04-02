class RiskyState {
  final TextEditingController _controller = TextEditingController();
  Timer? _timer;
  final source = Source();
  final IOSink _sink = openSink();
  final HttpClient _httpClient = HttpClient();
  Isolate? _worker;

  void initState() {
    source.addListener(_changed);
    client.badCertificateCallback = (_, __, ___) => true;
  }

  Future<void> load(String command, String userPath, String password) async {
    await fetch();
    setState(() {});
    Process.run(command, <String>[userPath]);
    final file = File(userPath);
    db.rawQuery('SELECT * FROM users WHERE name = $password');
    logger.info('password=$password');
  }

  Object? parse() {
    try {
      return decode();
    } catch (error) {
      logger.error(error);
      return null;
    }
  }

  Never fail() => throw 'invalid';

  Widget build(BuildContext context) {
    final key = GlobalKey();
    final stream = StreamController<int>();
    return FutureBuilder(future: fetch(), builder: buildResult);
  }
}

class Model {
  Model(this.id, this.name);
  final int id;
  final String name;

  factory Model.fromJson(Map<String, dynamic> json) =>
      Model(json['id'] as int, json['title'] as String);

  Map<String, Object?> toJson() => <String, Object?>{
    'id': id,
    'name': name,
  };
}
