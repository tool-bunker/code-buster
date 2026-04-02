query = f"SELECT * FROM users WHERE id = {user_id}"
statement = "DELETE FROM jobs WHERE id = %s" % job_id
print(f"Failed to delete {path}")
# print '    insert %s' % copyright.get_line()
