using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace PoetAndDidntKnowIt
{
    class MachineCrypt : ICrypt
    {

        public byte[] Encrypt(string clearText)
        {
            var bytes = HttpServerUtility.UrlTokenDecode(MachineKeyWrapper.EncryptString(clearText));
            return Enumerable.Repeat<byte>(0, Program.BlockSize).Concat(bytes).ToArray();
        }
        public string Decrypt(byte[] iv, byte[] cipher)
        {
            return MachineKeyWrapper.DecryptString(HttpServerUtility.UrlTokenEncode(iv.Concat(cipher).ToArray()));
        }
    }

}

