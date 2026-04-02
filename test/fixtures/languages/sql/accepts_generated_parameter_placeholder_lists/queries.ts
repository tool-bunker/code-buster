const placeholders = ids.map(() => '?').join(',');
db.prepare(`SELECT * FROM users WHERE id IN (${placeholders})`).all(...ids);
db.prepare(`SELECT * FROM users WHERE id IN (${ids.map(() => '?').join(',')})`).all(...ids);
db.prepare(`SELECT * FROM users WHERE id = ${userId}`);
