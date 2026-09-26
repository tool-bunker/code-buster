using System.IO.Compression;

class Archives
{
    void Unsafe(ZipArchive archive, string root)
    {
        foreach (var entry in archive.Entries)
        {
            var relative = entry.FullName.Split('/')[1];
            var outputPath = Path.Combine(root, relative);
            entry.ExtractToFile(outputPath, true);
        }
    }

    void UnsafeInline(ZipArchiveEntry entry, string root)
    {
        entry.ExtractToFile(Path.Combine(root, entry.FullName), true);
    }

    void EntryBasename(ZipArchiveEntry entry, string root)
    {
        entry.ExtractToFile(Path.Combine(root, entry.Name), true);
    }

    void FixedDestination(ZipArchiveEntry entry, string root)
    {
        entry.ExtractToFile(Path.Combine(root, "application.exe"), true);
    }

    void Validated(ZipArchiveEntry entry, string root)
    {
        var rootPath = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        var outputPath = Path.GetFullPath(Path.Combine(rootPath, entry.FullName));
        if (!outputPath.StartsWith(rootPath, StringComparison.Ordinal))
        {
            throw new InvalidDataException();
        }
        entry.ExtractToFile(outputPath, true);
    }

    // entry.ExtractToFile(Path.Combine(root, entry.FullName), true);
    const string Example = "entry.ExtractToFile(Path.Combine(root, entry.FullName), true)";
}
