var literalQuery = "SELECT name FROM sqlite_master " +
    "WHERE type = 'table'";
var dynamicQuery = "SELECT name FROM users WHERE name = '" + userName;
var interpolatedQuery = $"SELECT name FROM users WHERE name = '{userName}'";
