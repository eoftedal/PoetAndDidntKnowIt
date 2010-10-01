using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;


namespace PoetAndDidntKnowIt
{
    class Program
    {
        static int requests = 0;

        static void Main(string[] args)
        {
            MachineCrypt.Crypt();
            //AesCrypt();

            Console.ReadKey();
        }



        static void AesCrypt() {

            var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.GenerateIV();
            aes.GenerateKey();
            aes.Padding = PaddingMode.PKCS7;
            var encryptor = aes.CreateEncryptor();
            var clearText = Encoding.UTF8.GetBytes("Hello world! I am a bastard");
            var encrypted = encryptor.TransformFinalBlock(clearText, 0, clearText.Length);

            var enc = aes.IV.Concat(encrypted).ToArray();

            var blocks = (int)Math.Ceiling(enc.Count() / 16.0);
            var lastBlock = enc.GetBlock(blocks - 1, 16);
            var mixBlock = enc.GetBlock(blocks - 2, 16);

            var padLength = FindPaddingLength(aes, mixBlock, lastBlock, lastBlock.Length - 1, 0);
            Console.WriteLine("Padding : " + padLength + " (" + requests + " requests)");
            //var result = new List<byte>();
            var res = new byte[blocks -1][];
            Parallel.For<int>(1, blocks, () => 0, (ixx, loop, k) =>
                    {
                        res[ixx -1] = DecryptBlock(aes, enc, ixx, padLength);
                        return k;
                    }
                , x => { }
                );

            var result = res.SelectMany(x => x).ToList();
            result = result.TakeWhile((b, ix) => ix < (result.Count - padLength)).ToList();

            Console.WriteLine();
            Console.WriteLine("Requests: " + requests + " (" + ((double)requests / encrypted.Length) + " req/byte)");
            Console.WriteLine("Dec     : " + UTF8Encoding.UTF8.GetString(result.ToArray(), 0, result.Count));

            var decrypted = aes.CreateDecryptor().TransformFinalBlock(encrypted, 0, encrypted.Length);
            Console.WriteLine("Real    : " + UTF8Encoding.UTF8.GetString(decrypted, 0, decrypted.Length));


        }

        private static byte[] DecryptBlock(Aes aes, byte[] encrypted, int blockNum, int padLength)
        {
            var block = encrypted.GetBlock(blockNum, 16);
            var iv = encrypted.GetBlock(blockNum - 1, 16);
            var rnd = new Random();
            var newIv = aes.IV.Select(x => (byte) rnd.Next(0, 255)).ToArray();

            var result = new byte[block.Length];
            for (var i = 1; i <= block.Length; i++)
            {
                var r = newIv[newIv.Length - i];
                byte lastByte = 0;
                int curByte = newIv.Length - i;
                for (var j = 255; j >= 0; j--)
                {
                    newIv[curByte] = (byte)(r ^ j);
                    if (IsPaddingValid(aes.CreateDecryptor(aes.Key, newIv), block))
                    {
                        lastByte = (byte)(newIv[curByte] ^ i ^ iv[curByte]);
                        Console.WriteLine((16 - i).ToString("00") + ": " + lastByte.ToString("000") + " - rounds: " + (256 -j) + "");
                        break;
                    }
                }
                result[curByte] = (byte)lastByte;
                for (var k = 1; k <= i; k++)
                {
                    newIv[result.Length - k] = (byte)((newIv[newIv.Length - k] ^ (i)) ^ (i + 1));
                }
            }
            return result;
        }
         private static bool IsPaddingValid(ICryptoTransform decryptor, byte[] byteArray)
        {
            try
            {
                lock (typeof(Program))
                {
                    requests++;
                }
                decryptor.TransformFinalBlock(byteArray, 0, byteArray.Length);
                return true;
            }
            catch(CryptographicException ex)
            {
                return false;
            }

        }
        private static int FindPaddingLength(Aes aes, byte[] iv, byte[] dec, int i, int j)
        {
            if (i == j) return i;
            var m = (int)Math.Ceiling((i + j)/2.0);
            var ivm = iv.Select(x => x).ToArray();
            ivm[iv.Length - m] = (byte)(~ivm[iv.Length - m]);
            if (!IsPaddingValid(aes.CreateDecryptor(aes.Key, ivm), dec))
            {
                return FindPaddingLength(aes, iv, dec, i, m);
            }
            return FindPaddingLength(aes, iv, dec, m-1, j);
        }


    }
    public static class ByteHelper
    {
        public static byte[] GetBlock(this byte[] bytes, int num, int blockSize)
        {
            return bytes.Skip(num * blockSize).Take(blockSize).ToArray();
        }

    }
}

