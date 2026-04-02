const LIMIT = 5_000;
const TABLES = ['daily_counts', 'daily_events'] as const;
for (const table of TABLES) {
  db.prepare(`DELETE FROM ${table} WHERE day = ?`).run(day);
}
db.prepare(`DELETE FROM events WHERE id IN (SELECT id FROM events LIMIT ${LIMIT})`);
