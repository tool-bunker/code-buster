SELECT * FROM users WHERE name LIKE '%bob';
DELETE FROM sessions;
UPDATE accounts SET active = false;
DROP TABLE audit;
CREATE INDEX idx_users_name ON users(name);
ALTER TABLE users ADD COLUMN enabled boolean NOT NULL DEFAULT true;
