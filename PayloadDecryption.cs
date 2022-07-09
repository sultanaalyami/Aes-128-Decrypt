using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aes128Decrypt
{
    public class PayloadDecryption
    {
        public static string OpenSSLDecrypt(string payload,string ClientSecret)
        {
            string padding= payload.Replace("-", "+").Replace("_", "/");
            padding = padding.PadRight(padding.Length + (4 - (padding.Length % 4)), '=');
            var decoded = padding.DecodeBase64;
            var ivScout = decoded.ToString().Substring(0, 16);
            ClientSecret = ClientSecret.Substring(0, 16);
            byte[] iv = Encoding.ASCII.GetBytes(ivScout);
            byte[] key = Encoding.ASCII.GetBytes(ClientSecret);

            var json = OpenSSL.OpenSSLDecrypt(padding, key, iv);

            var revised = json.Substring(json.IndexOf('{'));
            return revised; 
        }

    }
}
