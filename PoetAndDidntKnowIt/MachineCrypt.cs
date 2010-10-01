using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PoetAndDidntKnowIt
{
    class MachineCrypt
    {
        public static int requests = 0;
        private const int blockSize = 16;
        public static void Crypt()
        {
            byte[] encOnly = HttpEncode.UrlTokenDecode(MachineKeyWrapper.EncryptString("Jeg liker donuts! Og jeg er en diger fisk med eggesmør!"));
            var enc = Enumerable.Repeat(0, 16).Select(i => (byte)i).Concat(encOnly).ToArray();

            var blocks = (int)Math.Ceiling((double)enc.Count() / blockSize);
            var lastBlock = enc.GetBlock(blocks - 1, blockSize);
            var mixBlock = enc.GetBlock(blocks - 2, blockSize);

            var padLength = FindPaddingLength(mixBlock, lastBlock, lastBlock.Length - 1, 0);
            Console.WriteLine("Padding : " + padLength + " (" + requests + " requests)");

            var res = new byte[blocks - 1][];
            Parallel.For<int>(1, blocks, 
                () => 0,
                (ixx, loop, k) =>
                {
                    res[ixx - 1] = DecryptBlock(enc, ixx, padLength);
                    return k;
                }, 
                x => { });

            var result = res.SelectMany(x => x).ToList();
            result = result.TakeWhile((b, ix) => ix < (result.Count - padLength)).ToList();

            Console.WriteLine();
            Console.WriteLine("Requests: " + requests + " (" + ((double)requests / enc.Length) + " req/byte)");
            Console.WriteLine("Dec     : " + UTF8Encoding.UTF8.GetString(result.ToArray(), 0, result.Count));

            var decrypted = MachineKeyWrapper.DecryptString(HttpEncode.UrlTokenEncode(encOnly));
            Console.WriteLine("Real    : " + decrypted);
        }

        private static byte[] DecryptBlock(byte[] encrypted, int blockNum, int padLength)
        {
            var block = encrypted.GetBlock(blockNum, blockSize);
            var iv = encrypted.GetBlock(blockNum - 1, blockSize);
            var rnd = new Random();
            var newIv = (new byte[blockSize]).Select(x => (byte)rnd.Next(0, 255)).ToArray();

            var result = new byte[block.Length];
            for (var i = 1; i <= block.Length; i++)
            {
                var r = newIv[newIv.Length - i];
                byte lastByte = 0;
                int curByte = newIv.Length - i;
                for (var j = 255; j >= 0; j--)
                {
                    newIv[curByte] = (byte)(r ^ j);
                    if (IsPaddingValid(newIv, block))
                    {
                        lastByte = (byte)(newIv[curByte] ^ i ^ iv[curByte]);
                        Console.WriteLine((blockSize - i).ToString("00") + ": " + lastByte.ToString("000") + " - rounds: " + (256 - j) + "");
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
        private static bool IsPaddingValid(byte[] iv, byte[] byteArray)
        {
            try
            {
                requests++;
                MachineKeyWrapper.DecryptString(HttpEncode.UrlTokenEncode(iv.Concat(byteArray).ToArray()));
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }

        }
        private static int FindPaddingLength(byte[] iv, byte[] dec, int i, int j)
        {
            if (i == j) return i;
            var m = (int)Math.Ceiling((i + j) / 2.0);
            var ivm = iv.Select(x => x).ToArray();
            ivm[iv.Length - m] = (byte)(~ivm[iv.Length - m]);
            if (!IsPaddingValid(ivm, dec))
            {
                return FindPaddingLength(iv, dec, i, m);
            }
            return FindPaddingLength(iv, dec, m - 1, j);
        }


    }

}

