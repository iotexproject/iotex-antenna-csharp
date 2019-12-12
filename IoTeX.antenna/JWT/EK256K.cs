using System;
using System.Collections.Generic;
using System.Text;
using IoTeX.antenna.Accounts;
using JWT;
using JWT.Serializers;
using Nethereum.Hex.HexConvertors.Extensions;

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

        public static Dictionary<string, object> Verify(string token)
        {
            IJsonSerializer serializer = new JsonNetSerializer();
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();

            var segments = token.Split('.');

            if (segments.Length != 3)
            {
                throw new Exception("token invalid");
            }
            
            var header = serializer.Deserialize<Dictionary<string, string>>(
                System.Text.Encoding.UTF8.GetString(urlEncoder.Decode(segments[0])));
            if (header["alg"] != "EK256K")
            {
                throw new Exception("alg should be EK256K but got " + header["alg"]);
            }

            
            var payload = serializer.Deserialize<Dictionary<string, object>>(
                System.Text.Encoding.UTF8.GetString(urlEncoder.Decode(segments[1])));
            var signature = urlEncoder.Decode(segments[2]);

            var empty = new Account();
            var recoveredAddress = empty.Recover(segments[0] + "." + segments[1], signature, false);
            
            var secretOrPublicKey = payload["iss"].ToString();
            var expectedAddress = Account.PublicKeyToAddress(secretOrPublicKey.HexToByteArray());
            if (recoveredAddress != expectedAddress) 
            {
                throw new Exception(recoveredAddress + " signed the signature but we are expecting " + expectedAddress);
            }
            if (payload["iss"].ToString() != secretOrPublicKey) {
                throw new Exception("issuer of the token does not match " + secretOrPublicKey);
            }
            return payload;
        }
    }
}