await db.Database.ExecuteSqlInterpolatedAsync(
    $"INSERT INTO Users (Id) VALUES ({userId})");
db.Database.ExecuteSqlInterpolated($"DELETE FROM Users WHERE Id = {userId}");
await db.Database.ExecuteSqlRawAsync(
    $"UPDATE Users SET Name = {userName} WHERE Id = {userId}");
var query = $"SELECT * FROM Users WHERE Id = {userId}";
