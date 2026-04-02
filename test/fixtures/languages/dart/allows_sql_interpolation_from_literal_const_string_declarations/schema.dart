const String logTable = 'logs';

class Schema {
  static const String idColumn = '_id';
  static const String messageColumn = 'message';

  void create() {
    db.execute(
      'create table $logTable (${Schema.idColumn} integer, $messageColumn text)',
    );
  }
}
