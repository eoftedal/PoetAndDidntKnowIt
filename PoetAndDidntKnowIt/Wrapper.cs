using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
using System.Web.Configuration;
using System.Configuration;

namespace PoetAndDidntKnowIt
{
    class MachineKeyWrapper
    {
        private static MethodInfo _encrypt;
        private static MethodInfo _decrypt;

        static MachineKeyWrapper()
        {
            MachineKeySection config = (MachineKeySection)ConfigurationManager.GetSection("system.web/machineKey");
            Type machineKeyType = config.GetType().Assembly.GetType("System.Web.Configuration.MachineKeySection");
            BindingFlags bf = BindingFlags.NonPublic | BindingFlags.Static;
            _encrypt = typeof(System.Web.UI.Page).GetMethod("EncryptString", bf, null, new[] { typeof(string) }, null);
            _decrypt = typeof(System.Web.UI.Page).GetMethod("DecryptString", bf, null, new[] { typeof(string) }, null);
        }

        public static string EncryptString(string s)
        {
            return (string)_encrypt.Invoke(null, new[] { s });
        }
        public static string DecryptString(string s)
        {
            return (string)_decrypt.Invoke(null, new[] { s });
        }
    }
}
