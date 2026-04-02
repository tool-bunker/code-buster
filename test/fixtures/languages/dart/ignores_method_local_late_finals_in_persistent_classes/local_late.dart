class DownloadEntry {
  DownloadEntry(this.id);

  factory DownloadEntry.fromJson(Map<String, Object?> json) =>
      DownloadEntry(json['id'] as int);

  final int id;

  Map<String, Object?> toJson() => <String, Object?>{'id': id};

  String outputPath(bool episode) {
    late final String directory;
    if (episode) {
      directory = 'episode';
    } else {
      directory = 'video';
    }
    return directory;
  }
}
