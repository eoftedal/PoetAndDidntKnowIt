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
        public const int BlockSize = 16;
        
        //private static ICrypt cryptoProvider = new AesCrypt();
        private static ICrypt cryptoProvider = new MachineCrypt();

        static void Main(string[] args)
        {
            var clearText = "This is a sample message";
            byte[] enc = cryptoProvider.Encrypt(clearText);

            var blocks = (int)Math.Ceiling((double)enc.Count() / BlockSize);
            var lastBlock = enc.GetBlock(blocks - 1, BlockSize);
            var mixBlock = enc.GetBlock(blocks - 2, BlockSize);

            var padLength = FindPaddingLength(mixBlock, lastBlock, lastBlock.Length - 1, 0);
            Console.WriteLine("Padding : " + padLength + " (" + requests + " requests)");

            var res = new byte[blocks - 1][];
            Parallel.For(1, blocks, 
                i => res[i - 1] = DecryptBlock(enc, i, padLength)
                );

            var result = res.SelectMany(x => x).ToList();
            result = result.TakeWhile((b, ix) => ix < (result.Count - padLength)).ToList();

            Console.WriteLine();
            Console.WriteLine("Requests  : " + requests + " (" + ((double)requests / enc.Length) + " req/byte)");
            Console.WriteLine("Decrypted : " + UTF8Encoding.UTF8.GetString(result.ToArray(), 0, result.Count));

            Console.ReadKey();
        }

        public static bool IsPaddingValid(byte[] iv, byte[] byteArray)
        {
            try
            {
                requests++;
                cryptoProvider.Decrypt(iv, byteArray);
                return true;
            }
            catch (Exception)
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

        private static byte[] DecryptBlock(byte[] encrypted, int blockNum, int padLength)
        {
            var block = encrypted.GetBlock(blockNum, BlockSize);
            var iv = encrypted.GetBlock(blockNum - 1, BlockSize);
            var rnd = new Random();
            var newIv = (new byte[BlockSize]).Select(x => (byte)rnd.Next(0, 255)).ToArray();

            var result = new byte[block.Length];
            for (var i = 1; i <= block.Length; i++)
            {
                int curByte = newIv.Length - i;
                var r = newIv[curByte];
                int lastByte = -1;
                for (var j = 255; j >= 0; j--)
                {
                    newIv[curByte] = (byte)(r ^ j);
                    if (IsPaddingValid(newIv, block))
                    {
                        lastByte = (byte)(newIv[curByte] ^ i ^ iv[curByte]);
                        Console.WriteLine((BlockSize - i).ToString("00") + ": " + lastByte.ToString("000") + " - rounds: " + (256 - j) + "");
                        break;
                    }
                }
                if (lastByte == -1) throw new Exception("Could not decrypt this blocK");
                result[curByte] = (byte)lastByte;
                for (var k = 1; k <= i; k++)
                {
                    newIv[result.Length - k] = (byte)((newIv[newIv.Length - k] ^ (i)) ^ (i + 1));
                }
            }
            return result;
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

