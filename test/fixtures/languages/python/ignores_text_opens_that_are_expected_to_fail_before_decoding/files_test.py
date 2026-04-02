with self.assertRaises(FileNotFoundError):
    open(missing_path, "r")
with open(existing_path, "r") as source:
    source.read()
