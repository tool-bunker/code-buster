DO $$
BEGIN
  IF true THEN
    ALTER TABLE users ADD COLUMN enabled boolean NOT NULL DEFAULT true;
  END IF;
END $$;
