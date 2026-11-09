namespace PolicyVice.Tests
{
    using System;

    public static class T
    {
        public static int Passed, Failed;

        public static void Check(bool ok, string what)
        {
            if (ok) Passed++;
            else
            {
                Failed++;
                Console.WriteLine("FAIL: " + what);
            }
        }
    }

    public static class Program
    {
        public static int Main(string[] args)
        {
            CoreTests.Run(args);
            DeviceTests.Run();
            CatalogTests.Run();
            ImeTests.Run();
            EnrichTests.Run();
            ReviewTests.Run();
            NamesTests.Run();
            Console.WriteLine(T.Passed + " passed, " + T.Failed + " failed");
            return T.Failed == 0 ? 0 : 1;
        }
    }
}
