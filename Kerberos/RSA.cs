using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Kerberos
{
    public class RSA
    {
        // Шифрование
        public static BigInteger Encrypt(BigInteger message, BigInteger[] key)
        {
            // Модуль n и показатель степени e из ключа
            BigInteger n = key[0];
            BigInteger e = key[1];

            // Шифрование: c = m^e mod n 
            return BigInteger.ModPow(message, e, n);
        }
    }
}
