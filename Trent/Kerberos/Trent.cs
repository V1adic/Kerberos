using Newtonsoft.Json;
using System.Collections;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos
{
    public class Record(string? Identificatory, BigInteger[] publicKey)
    {
        public string? Identificatory = Identificatory;
        public BigInteger[] publicKey = publicKey;
    }

    public class Trent : IDisposable
    {
        private const string fileUsers = "Data/Users.json";
        private readonly List<Record> _records;
        private static readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        private static Trent? _instance;
        private static readonly object _lock = new();
        private bool _disposed = false;

        private Trent()
        {
            _records = LoadRecords();
            AppDomain.CurrentDomain.ProcessExit += (s, e) => SaveRecords();
        }

        public static Trent Instance
        {
            get
            {
                lock (_lock)
                {
                    _instance ??= new Trent();
                    return _instance;
                }
            }
        }

        private static BigInteger ConvertStringToBigInteger(string input)
        {
            // Преобразуем строку в массив байтов
            byte[] byteArray = Encoding.UTF8.GetBytes(input);
            // Возвращаем значение BigInteger из массива байтов
            return new BigInteger(byteArray, isUnsigned: true);
        }

        private static List<Record> LoadRecords()
        {
            List<Record> result;
            if (File.Exists(fileUsers))
            {
                var jsonData = File.ReadAllText(fileUsers);
                result = JsonConvert.DeserializeObject<List<Record>>(jsonData) ?? [];
            }
            else
            {
                result = [];
            }

            return result;
        }

        private void DisplayRecords()
        {
            foreach (var record in _records)
            {
                Console.Write(record.Identificatory + ":");
                foreach (var value in record.publicKey)
                {
                    Console.Write($" {value}");
                }
                Console.WriteLine();
            }
        }

        private void SaveRecords()
        {
            try
            {
                var jsonData = JsonConvert.SerializeObject(_records, Formatting.Indented);
                using var writer = new StreamWriter(fileUsers);
                writer.Write(jsonData);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при записи в файл {fileUsers}: {ex.Message}");
            }
        }

        public void AddRecord(Record rec)
        {
            if (rec == null)
            {
                throw new ArgumentNullException(nameof(rec), "Record cannot be null");
            }

            lock (_lock) 
            {
                _records.RemoveAll(record => record.Identificatory == rec.Identificatory);
                _records.Add(rec);
            }
        }

        public (BigInteger, BigInteger) GetKey(string IdAlice, string IdBob)
        {
            Record? recordAlice;
            Record? recordBob;

            lock (_lock)
            {
                recordAlice = _records.FirstOrDefault(r => r.Identificatory == IdAlice);
                recordBob = _records.FirstOrDefault(r => r.Identificatory == IdBob);
            }
            if (recordAlice == null)
            {
                throw new Exception($"Record with Identificatory {IdAlice} not found.");
            }
            if (recordBob == null)
            {
                throw new Exception($"Record with Identificatory {IdBob} not found.");
            }

            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            int delta = 86400000;
            byte[] randomBytes = new byte[32];
            rng.GetBytes(randomBytes);
            BigInteger key = new(randomBytes, isUnsigned: true);

            string resultAlice = $"{timestamp} {delta} {key} {IdBob}";
            string resultBob = $"{timestamp} {delta} {key} {IdAlice}";

            return (RSA.Encrypt(ConvertStringToBigInteger(resultAlice), recordAlice.publicKey), RSA.Encrypt(ConvertStringToBigInteger(resultBob), recordBob.publicKey));
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    SaveRecords();
                }
                _disposed = true;
            }
        }
    }
}