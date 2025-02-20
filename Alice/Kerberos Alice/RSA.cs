using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Kerberos_Alice
{
    public class RSA
    {
        // Генерация ключей
        public static (BigInteger[], BigInteger[]) GenerateKeys()
        {
            // Выбираются два больших случайных простых числа p и q
            BigInteger p = BigInteger.Parse("695125787832798119886798054834278528315076653258754859131353533288441366410834938909176443369324577143349217008557326624683520686813952813205880343712509");
            BigInteger q = BigInteger.Parse("565553156847291254295414270550436950418934096740191387045196483873028525604564353240808261090019243544886490937722626462848499227835404570945343523733793");

            // Вычисление модуля n = p  q
            BigInteger n = p * q;

            // Вычисление функции Эйлера от n: φ(n) = (p - 1) * (q - 1)
            BigInteger phi = (p - 1) * (q - 1);

            // Выбирается случайное число e, взаимно простое с φ(n) и 1 < e < φ(n)
            BigInteger e = BigInteger.Parse("9533057111911815874266958027271625427196067777799480980121965211296384601904725464786065568680909682793317818368481813797887317657214326868862887696208907");

            // Вычисление секретного ключа d, обратного к e по модулю φ(n)
            BigInteger d = ModInverse(e, phi);

            // Возвращается открытый ключ (n, e) и закрытый ключ (n, d)
            return ([n, e], [n, d]);
        }

        // Шифрование
        public static BigInteger Encrypt(BigInteger message, BigInteger[] key)
        {
            // Модуль n и показатель степени e из ключа
            BigInteger n = key[0];
            BigInteger e = key[1];

            // Шифрование: c = m^e mod n
            return BigInteger.ModPow(message, e, n);
        }

        // Вычисление модульного обратного
        private static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            BigInteger m0 = m;
            BigInteger y = 0;
            BigInteger x = 1;

            // Используем алгоритм расширенного алгоритма Евклида для вычисления обратного
            if (m == 1)
            {
                return 0;
            }

            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;
                m = a % m;
                a = t;
                t = y;
                y = x - q * y;
                x = t;
            }

            // Если x отрицательное, добавляем m, чтобы получить положительное значение
            if (x < 0)
            {
                x += m0;
            }

            return x;
        }
    }
}
