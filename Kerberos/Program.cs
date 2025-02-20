using System.Numerics;

namespace Kerberos
{
    internal class Program
    {
        static async Task Main()
        {
            int port = 11000;
            Console.WriteLine("Запуск сервера....");
            using (TcpServer server = new(port))
            {
                Task servertask = server.ListenAsync();
                while (true)
                {
                    string? input = Console.ReadLine();
                    if (input == "stop")
                    {
                        Console.WriteLine("Остановка сервера...");
                        server.Stop();
                        break;
                    }
                }
                await servertask;
            }
            Console.WriteLine("Нажмите любую клавишу для выхода...");
            Console.ReadKey(true);
        }
    }
}
