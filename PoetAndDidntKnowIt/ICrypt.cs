using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PoetAndDidntKnowIt
{
    interface ICrypt
    {
        byte[] Encrypt(string clearText);
        string Decrypt(byte[] iv, byte[] cipher);
    }
}
