/*
  Warnings:
  - Added the required column without a default value.
*/
ALTER TABLE users ADD COLUMN role TEXT NOT NULL;
SELECT '/* DEFAULT inside a literal is not a comment */';
ALTER TABLE users ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT true;
