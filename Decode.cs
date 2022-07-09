using Microsoft.AspNetCore.WebUtilities;
using System.Text;

namespace Aes128Decrypt
{
    public static class Decode
    {
        // base 64 decode
        public static string DecodeBase64(this string value)
        {
            byte[] valueBytes = WebEncoders.Base64UrlDecode(value);
            return Encoding.UTF8.GetString(valueBytes);
        }
    }
}