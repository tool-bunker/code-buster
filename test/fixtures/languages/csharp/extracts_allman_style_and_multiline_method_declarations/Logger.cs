class Logger
{
    internal static void Write(
        string message,
        bool enabled)
    {
        if (enabled)
        {
            Save(message);
        }
    }

    /// Returns (success, count).
    public (bool Success, int Count) Read<T>()
        where T : class, new()
    {
        return (true, 1);
    }
}
