const int pageSize = 100;
var offset = 0;
var ticks = DateTime.Now.Date.Ticks;
var pageQuery = $"SELECT * FROM Items LIMIT {pageSize} OFFSET {offset}";
var kindQuery = $"DELETE FROM Items WHERE Kind = {(int)ItemKind.Archived}";
var cleanupQuery = $"UPDATE Items SET Seen = 0 WHERE SeenAt < {ticks}";
var unsafeQuery = $"SELECT * FROM Items WHERE Owner = '{owner}'";
