﻿using System.Net.Http;
using System.Net.Sockets;
using System.Text;

namespace Kerberos_Alice
{
    internal class Program
    {
        public static Connection? _instanceBob;
        public static Connection? _instance;

        static async Task Main()
        {
            var instance = new Alice();
            using TcpClient tcpClient = new("192.168.1.58", 11000); // IP_Server
            _instance = new(tcpClient);

            using TcpClient tcpClientBob = new("192.168.1.2", 11000); // IP_BOB
            _instanceBob = new(tcpClientBob);

            //using _TcpServer server = new(11001);
            Console.WriteLine("Запуск клиента....");
            try
            {
                //byte[] result = Encoding.UTF8.GetBytes($"/Sync {instance._publicKey[0]} {instance._publicKey[1]}");
                //await _instance.SendMessageAsync(result);
                //Task serverTask = server.ListenAsync();

                await _instance.SendMessageAsync(Encoding.UTF8.GetBytes($"/GetKey 192.168.1.162 192.168.1.2"));

                while (true)
                {
                    string? input = Console.ReadLine();
                    if (input != null) 
                    {
                        if (input.Length == 0)
                        {
                            //server.Stop();
                            break;
                        }
                    }
                }

                //await serverTask;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            Console.WriteLine("Нажмите любую клавишу для выхода...");
            Console.ReadKey(true);
        }
    }
}
