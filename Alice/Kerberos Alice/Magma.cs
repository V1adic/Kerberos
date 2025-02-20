using System;
using System.Collections.Generic;

namespace Kerberos_Alice
{
    public class Magma // Класс шифрации, дешифрации
    {
        private const ulong Mod32 = 0xffffffff; // 2^32
        private readonly ulong Imit;
        private readonly ulong[] Key; // Раундовые ключи
        private static readonly int[][] S_Block =
        [
            [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
            [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
            [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
            [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
            [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
            [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
            [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
            [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
        ];

        public Magma(ulong[] Keys, ulong Imit)
        {
            Key = new ulong[32];
            this.Imit = Imit;
            SetKeys(Keys);
        }

        private void SetKeys(ulong[] Keys)
        {
            for (int i = 0; i < 24; ++i) // Сочетания раундовых ключей
            {
                Key[i] = Keys[i % 8];
            }
            for (int i = 7; i >= 0; --i) // Послейдние 8 раундов обратные
            {
                Key[32 - i - 1] = Keys[i];
            }
        }

        private static ulong Function(ulong data, ulong key) // Функция S-block и прочее
        {
            data += key; // Сложение по модулю 2^32
            data &= Mod32;

            int[] un = new int[8]; // Для S-block
            for (int i = 0; i < 8; ++i)
            {
                key = data & 0xf; // Берем последние 4 бита
                un[8 - i - 1] = (int)key; // Записываем
                data >>= 4; // Смещаем записанное
            }

            for (int i = 0; i < 8; ++i) // Цикл прохождения через S-block
            {
                un[i] = S_Block[i][un[i]];
            }

            for (int i = 0; i < 8; ++i) // Поочередно записываем в data
            {
                data += (ulong)un[i];
                data <<= 4;
            }
            data >>= 4; // Лишний раз сместились

            data = data << 11 | data >> 21; // Циклическое смещение на 11
            data &= Mod32; // Лишнее обрезать
            return data;
        }

        private ulong Round(ulong left, ulong right, bool flag) // Функция раунда
        {
            if (flag) // Если декодируем
            {
                //reverse xkey
                for (int i = 8; i < 16; ++i)
                {
                    (Key[i], Key[32 - i - 1]) = (Key[32 - i - 1], Key[i]);
                }
            }

            for (int i = 0; i < 31; ++i) // 31 раз меняем местами блоки
            {
                (left, right) = (right, left ^ Function(right, Key[i])); // Меняем местами и ксорим функцию
            }

            left ^= Function(right, Key[31]); // Последний блок не меняем
            left <<= 32;
            left += right; // Записываем в одно

            if (flag) // Если декодируем нужно все вернуть на место
            {
                //reverse xkey
                for (int i = 8; i < 16; ++i)
                {
                    (Key[i], Key[32 - i - 1]) = (Key[32 - i - 1], Key[i]);
                }
            }
            return left;
        }

        private ulong Encrypt(ulong data) // Функция кодирования 
        {
            ulong left = data;
            ulong right = left & Mod32;
            left >>= 32;
            data = Round(left, right, false);
            return data;
        }

        private ulong Decrypt(ulong data) // Функция декодирования
        {
            ulong left = data;
            ulong right = left & Mod32;
            left >>= 32;
            data = Round(left, right, true);
            return data;
        }

        private static List<ulong> ToULongList(byte[] bytes)
        {
            var ulongList = new List<ulong>();
            int padding = (8 - bytes.Length % 8) % 8; // Колличество нулей

            var paddedBytes = new byte[bytes.Length + padding];
            Array.Copy(bytes, paddedBytes, bytes.Length);

            for (int i = 0; i < paddedBytes.Length; i += 8)
            {
                ulongList.Add(BitConverter.ToUInt64(paddedBytes, i));
            }

            return ulongList;
        }
        private static byte[] ToByteArray(List<ulong> ulongList)
        {
            var bytes = new byte[ulongList.Count * 8];
            for (int i = 0; i < ulongList.Count; i++)
            {
                BitConverter.GetBytes(ulongList[i]).CopyTo(bytes, i * 8);
            }
            return bytes;
        }

        public byte[] Magma_Encrypt(byte[] value) // Функция шифрования текста
        {
            if (value.Length % 8 != 0)
            {
                Console.WriteLine("Длинна вашего файла не кратна 64 битам. Возможны проблемы!");
            }

            List<ulong> text = ToULongList(value);

            ulong old = Imit; // Передали в конструкторе

            for (int i = 0; i < text.Count; i++)
            {
                text[i] = text[i] ^ old; // Сперва XOR с предыдущим блоком
                text[i] = Encrypt(text[i]); // Потом шифр
                old = text[i]; // Сохраняем наше предыдущее знаениче
            }

            byte[] result = ToByteArray(text);
            return result;
        }

        public byte[] Magma_Decrypt(byte[] value) // Функция дешифрования текста
        {
            if (value.Length % 8 != 0)
            {
                Console.WriteLine("Длинна вашего файла не кратна 64 битам. Возможны проблемы!");
            }

            List<ulong> text = ToULongList(value);

            ulong old = Imit; // Передали в конструкторе

            for (int i = 0; i < text.Count; i++)
            {
                var old1 = text[i]; // Предыдущее знаение следующего рауда -> Зашифрованное значение текущего
                text[i] = Decrypt(text[i]); // Расшифровываем что было
                text[i] = text[i] ^ old; // XOR с предыдущим зашифрованным значением
                old = old1; // Новое предыдущее зашифрованное значение
            }

            byte[] result = ToByteArray(text);
            return result;
        }
    }
}
