using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace PoetAndDidntKnowIt
{
    public class AesCrypt : ICrypt
    {
        Aes aes;

        public AesCrypt()
        {
            aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.GenerateIV();
            aes.GenerateKey();
            aes.Padding = PaddingMode.PKCS7;
        }

        public byte[] Encrypt(string clearText)
        {
            var bytes = Encoding.UTF8.GetBytes(clearText);
            var cipher = aes.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length);
            return aes.IV.Concat(cipher).ToArray();
        }
        public string Decrypt(byte[] iv, byte[] cipher)
        {
            var bytes = aes.CreateDecryptor(aes.Key, iv).TransformFinalBlock(cipher, 0, cipher.Length);
            return Encoding.UTF8.GetString(bytes);
        }

    }
}
