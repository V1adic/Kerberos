using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Kerberos_Alice
{
    public class Alice
    {
        public readonly BigInteger[] _publicKey;
        private readonly BigInteger[] _privateKey;
        private static readonly string filename = "Data/key.txt";

        public Alice()
        {
            if (!File.Exists(filename))
            {
                (_publicKey, _privateKey) = RSA.GenerateKeys();
                string result = $"{_publicKey[0]} {_publicKey[1]}\n{_privateKey[0]} {_privateKey[1]}";

                File.WriteAllText(filename, result);
            }
            else
            {
                var text = File.ReadAllText(filename);
                var keys = text.Split("\n");

                var publicKey = keys[0].Split(" ");
                var privateKey = keys[1].Split(" ");

                _publicKey = [BigInteger.Parse(publicKey[0]), BigInteger.Parse(publicKey[1])];
                _privateKey = [BigInteger.Parse(privateKey[0]), BigInteger.Parse(privateKey[1])];
            }
        }

        public string Encod(BigInteger data)
        {
            var res = RSA.Encrypt(data, _privateKey);
            var bytes = res.ToByteArray(isUnsigned: true);

            return Encoding.UTF8.GetString(bytes);
        }
    }
}
