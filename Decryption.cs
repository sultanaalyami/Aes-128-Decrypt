using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aes128Decrypt
{
    public static class Decryption 
    {

        public static string PayloadDecrypt(this PayloadData payload,string ClientSecret)
        {
            //Convert the raw data to the original base64 first
            string padding = payload.data.Replace("-", "+").Replace("_", "/");
            //For correct payload decryption, create additional padding to make the payload a multiple of 4:
            padding = padding.PadRight(padding.Length + (4 - (padding.Length % 4)), '=');
             

            // Initialization vector is the first 16 bytes of the received data
            var ivScout = padding.Substring(0, 16);

            // Initialization key 
            ClientSecret = ClientSecret.Substring(0, 16);

            // Get binary data
            byte[] iv = Encoding.ASCII.GetBytes(ivScout);
            byte[] key = Encoding.ASCII.GetBytes(ClientSecret);

            // Decrypt raw binary payload
 
            var json = padding.OpenSSLDecrypt(key, iv);

            var revised = json.Substring(json.IndexOf('{'));
            return revised; 
        }


    }
}
