const sources = <String, String>{
  'Queries.cs': r'''
var query = $"SELECT * FROM Users WHERE Id = {id}";
''',
  'queries.py':
      '''query = "SELECT * FROM " + table_name
''',
};
