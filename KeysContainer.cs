using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RSAEncryption
{
    public class KeysContainer
    {
        private string key;

        public string Key
        {
            get { return key; }
            set { key = value; }
        }

        private string iv;

        public string Iv
        {
            get { return iv; }
            set { iv = value; }
        }

        public KeysContainer(string _key, string _iv)
        {
            key = _key;
            iv = _iv;
        }

        public KeysContainer()
        {

        }
    }
}
