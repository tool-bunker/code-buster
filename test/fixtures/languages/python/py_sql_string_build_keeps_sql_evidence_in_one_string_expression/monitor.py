data = client.patch(f"/v2/monitor/{monitor_id}", payload, "update monitor")
data = await client.patch(f"/v2/monitor/{monitor_id}", payload, "update monitor")
print(f"Select an analysis option:")
query = f"SELECT * FROM users WHERE id = {user_id}"
query = "DELETE FROM jobs WHERE id = %s" % job_id
query = "SELECT * FROM " + table_name
