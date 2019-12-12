using System.Collections.Generic;
using System.Text;
using IoTeX.antenna.Accounts;
using JWT;
using JWT.Serializers;

namespace IoTeX.antenna.JWT
{
    public class EK256KAlgorithm
    {
        public byte[] Sign(string key, byte[] bytesToSign)
        {
            var account = Account.FromPrivateKey(key);
            var sign = account.Sign(bytesToSign);
            return sign;
        }
    }
    
    public class EK256K
    {
        public static string Sign(string key, Dictionary<string, object> payload)
        {
            var header = new Dictionary<string, object>
            {
                {"alg", "EK256K"},
                {"typ", "JWT"}
            };

            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            EK256KAlgorithm algorithm = new EK256KAlgorithm();

            var headerBase = urlEncoder.Encode(Encoding.ASCII.GetBytes(serializer.Serialize(header)));
            var payloadBase = urlEncoder.Encode(Encoding.ASCII.GetBytes(serializer.Serialize(payload)));
            var signature = algorithm.Sign(key, Encoding.ASCII.GetBytes(headerBase + "." + payloadBase));

            return headerBase + "." + payloadBase + "." + urlEncoder.Encode(signature);
        }
    }
}