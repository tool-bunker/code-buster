String select = "SELECT * FROM users WHERE id=" + id;
String insert = "INSERT INTO users VALUES (" + values;
String update = "UPDATE users SET name=" + name;
String delete = "DELETE FROM users WHERE id=" + id;
String parameterized = "SELECT * FROM users WHERE id=?";
String constantFragments = "SELECT * FROM " + "users";
out.println(msgPartOne + " Delete " + msgPartTwo);
throw new IllegalStateException("Delete failed for " + objectId);
LOGGER.info("update user " + id);
LOGGER.info("delete user " + id);
// update dp value for +1 length
int insertDistance = dp[i][j + 1] + 1;
int deleteDistance = dp[i + 1][j] + 1;
