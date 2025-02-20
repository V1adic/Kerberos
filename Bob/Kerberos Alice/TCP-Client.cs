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

namespace Kerberos_Alice
{
    public class Connection : IDisposable
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _stream;
        private readonly EndPoint? _remoteEndPoint;
        private readonly Task _readingTask;
        private readonly Task _writingTask;
        private readonly Channel<byte[]> _channel;
        private bool disposed;

        public Connection(TcpClient client)
        {
            _client = client;
            _stream = client.GetStream();
            _remoteEndPoint = client.Client.RemoteEndPoint;
            _channel = Channel.CreateUnbounded<byte[]>();
            _readingTask = RunReadingLoop();
            _writingTask = RunWritingLoop();
        }

        private async Task RunReadingLoop()
        {
            try
            {
                byte[] headerBuffer = new byte[4];
                while (true)
                {
                    int bytesReceived = await _stream.ReadAsync(headerBuffer);
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
                    string[] services = [];

                    if (message.Contains(' '))
                    {
                        services = message.Split(' ', 2);
                    }
                    else
                    {
                        services = [message];
                    }
                    switch (services[0])
                    {
                        case "/Error":
                            {
                                Console.WriteLine($"ERROR!!! -> {services[1]}");
                            }
                            break;

                        case "/GetKey":
                            {
                                var instance = new Alice();

                                var data = services[1].Split(" ");
                                string? ID = _remoteEndPoint?.ToString()?.Split(":")[0];
                                var messages = instance.Encod(BigInteger.Parse(data[0])).Split(" ");
                                var key = BigInteger.Parse(messages[2]);

                                byte[] bytes = key.ToByteArray();
                                ulong[] ulongArray = new ulong[bytes.Length / 4];
                                for (int i = 0; i < ulongArray.Length; i++)
                                {
                                    ulongArray[i] = BitConverter.ToUInt32(bytes, i * 4);
                                }
                                Magma Crypter = new(ulongArray, 0x7623784623764726);
                                string res = $"{messages[0]} {ID}";

                                var dat = Crypter.Magma_Encrypt(Encoding.UTF8.GetBytes(res));
                                var sertificat = Encoding.UTF8.GetString(dat);

                                #pragma warning disable CS8602 
                                await Program._instanceBob.SendMessageAsync(Encoding.UTF8.GetBytes($"/SetKey {data[1]} {sertificat}"));
                                #pragma warning restore CS8602
                            }
                            break;

                        case "/Result":
                            {
                                Console.WriteLine("ОБМЕНЯЛИСЬ КЛЮЧАМИ С БОБОМ!!!!");
                            }
                            break;
                    }

                }
                Console.WriteLine($"Сервер закрыл соединение.");
                _stream.Close();
            }
            catch (IOException)
            {
                Console.WriteLine($"Подключение закрыто.");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.GetType().Name + ": " + ex.Message);
            }
        }

        public async Task SendMessageAsync(byte[] message)
        {
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
