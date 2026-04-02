const String table = 'users';

void query(String column) {
  db.rawQuery('select $column from $table');
}

void shadow() {
  final table = runtimeTable();
  db.execute('delete from $table');
}

void concatenate(String suffix) {
  db.execute('select * from ' + suffix);
}
