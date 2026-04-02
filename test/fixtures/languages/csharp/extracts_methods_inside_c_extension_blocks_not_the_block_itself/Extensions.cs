public static class Extensions
{
    extension(string value)
    {
        public bool IsReady()
        {
            if (value.Length == 0) return false;
            return true;
        }
    }
}
