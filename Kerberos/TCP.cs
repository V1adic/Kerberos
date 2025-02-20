using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;
using System.Numerics;

namespace Kerberos
{
    class TcpServer(int port) : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Any, port);
        public static List<Connection> _clients = []; // это пул подключений, нужен чтобы нормально отключить всех подключенных при остановке сервера
        bool disposed;

        public async Task ListenAsync()
        {
            try
            {
                _listener.Start();
                Console.WriteLine("Сервер стартовал на " + _listener.LocalEndpoint);

                while (true)
                {
                    TcpClient client = await _listener.AcceptTcpClientAsync();
                    Console.WriteLine("Подключение: " + client.Client.RemoteEndPoint + " > " + client.Client.LocalEndPoint);
                    Connection? con = null;
                    lock (_clients)
                    {
                        con = new Connection(client, c => { _clients.Remove(c); c.Dispose(); });
                        _clients.Add(con);
                    }
                }
            }
            catch (SocketException)
            {
                Console.WriteLine("Сервер остановлен.");
            }
        }

        public void Stop()
        {
            _listener.Stop();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            disposed = true;
            _listener.Stop();
            if (disposing)
            {
                lock (_clients)
                {
                    if (_clients.Count > 0)
                    {
                        Console.WriteLine("Отключаю клиентов...");
                        foreach (Connection client in _clients)
                        {
                            client.Dispose();
                        }
                        Console.WriteLine("Клиенты отключены.");
                    }
                }
            }
        }

        ~TcpServer() => Dispose(false);
    }

    class Connection : IDisposable
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly EndPoint? _remoteEndPoint;
        private readonly Task _readingTask;
        private readonly Task _writingTask;
        private readonly Action<Connection> _disposeCallback;
        private readonly Channel<byte[]> _channel;
        bool disposed;

        public Connection(TcpClient client, Action<Connection> disposeCallback)
        {
            _client = client;
            _stream = client.GetStream();
            _remoteEndPoint = client.Client.RemoteEndPoint;
            _disposeCallback = disposeCallback;
            _channel = Channel.CreateUnbounded<byte[]>();
            _readingTask = RunReadingLoop();
            _writingTask = RunWritingLoop();
        }

        private async Task RunReadingLoop()
        {
            await Task.Yield();
            try
            {
                byte[] headerBuffer = new byte[4];
                while (true)
                {
                    int bytesReceived = await _stream.ReadAsync(headerBuffer.AsMemory(0, 4));
                    if (bytesReceived != 4)
                        break;
                    int length = BinaryPrimitives.ReadInt32LittleEndian(headerBuffer);
                    byte[] buffer = new byte[length];
                    int count = 0;
                    while (count < length)
                    {
                        bytesReceived = await _stream.ReadAsync(buffer.AsMemory(count, buffer.Length - count));
                        count += bytesReceived;
                    }
                    string message = Encoding.UTF8.GetString(buffer);

                    var services = message.Split(" ", 2);
                    switch (services[0])
                    {
                        case "/Sync":
                            {
                                try
                                {
                                    var TempKey = services[1].Split(" ", 2);
                                    Trent.Instance.AddRecord(new Record(_remoteEndPoint?.ToString()?.Split(":")[0], [BigInteger.Parse(TempKey[0]), BigInteger.Parse(TempKey[1])]));
                                }
                                catch
                                {
                                    await SendMessageAsync(Encoding.UTF8.GetBytes("/Error error sync"));
                                }
                            }
                            break;

                        case "/GetKey":
                            {
                                try
                                {
                                    var ID = services[1].Split(" ", 2);
                                    (BigInteger Alice, BigInteger Bob) = Trent.Instance.GetKey(ID[0], ID[1]);
                                    await SendMessageAsync(Encoding.UTF8.GetBytes($"/GetKey {Alice} {Bob}"));   
                                }
                                catch (Exception ex)
                                {
                                    await SendMessageAsync(Encoding.UTF8.GetBytes($"/Error {ex.Message}"));
                                }
                            }
                            break;
                    }
                }
                Console.WriteLine($"Клиент {_remoteEndPoint} отключился.");
                _stream.Close();
            }
            catch (IOException)
            {
                Console.WriteLine($"Подключение к {_remoteEndPoint} закрыто сервером.");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.GetType().Name + ": " + ex.Message);
            }
            if (!disposed)
                _disposeCallback(this);
        }

        public async Task SendMessageAsync(byte[] message)
        {
            //Console.WriteLine($">> {_remoteEndPoint}: {Encoding.UTF8.ToString(message)}");
            await _channel.Writer.WriteAsync(message);
        }

        private async Task RunWritingLoop()
        {
            byte[] header = new byte[4];
            await foreach (byte[] message in _channel.Reader.ReadAllAsync())
            {
                byte[] buffer = message;
                BinaryPrimitives.WriteInt32LittleEndian(header, buffer.Length);
                await _stream.WriteAsync(header);
                await _stream.WriteAsync(buffer);
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            disposed = true;
            if (_client.Connected)
            {
                _channel.Writer.Complete();
                _stream.Close();
                Task.WaitAll(_readingTask, _writingTask);
            }
            if (disposing)
            {
                _client.Dispose();
            }
        }

        ~Connection() => Dispose(false);
    }
}
