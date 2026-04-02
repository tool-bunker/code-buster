class SyncService {
  Map<String, Object?> toJsonRequest() => <String, Object?>{
    'status': 'ready',
  };

  String? fromJsonResponse(Map<String, Object?> data) =>
      data['message'] as String?;
}
