using System.Linq;
using System.Text;
using Crypto;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.RLP;
using Nethereum.Signer;
using Nethereum.Signer.Crypto;
using Nethereum.Util;

namespace IoTeX.antenna.Accounts
{
    public class Account: IAccount
    {
        public Account(string privateKey)
        {
            Initialise(new EthECKey(privateKey));
        }
        
        public static Account FromPrivateKey(string privateKey)
        { 
            return new Account(privateKey);
        }

        public static Account Generate()
        {
            return new Account(EthECKey.GenerateKey().GetPrivateKey());
        }

        private void Initialise(EthECKey key)
        {
            PrivateKey = key.GetPrivateKey();
            PublicKey = key.GetPubKey().ToHex();
            Address = Bech32.Encode("io", Hash.Hash160B(key.GetPubKey().Slice(1)));
        }

        public string Address { get; private set; }
        public string PrivateKey { get; private set; }
        public string PublicKey { get; private set; }
        
        public byte[] Sign(byte[] data)
        {
            var key = new EthECKey(this.PrivateKey);
            var signed = key.SignAndCalculateV(this.HashMessage(data));
            var result = new byte[signed.To64ByteArray().Length + 1];
            signed.To64ByteArray().CopyTo(result, 0);
            result[result.Length - 1] = (byte) (signed.V[0] - 27);
            return result;
        }

        public string Recover(string message, byte[] signature, bool preFixed)
        {
            var bytes = Encoding.ASCII.GetBytes(message);
            if (!preFixed) {
                bytes = this.HashMessage(bytes);
            }

            var ecdaSignature = EthECDSASignatureFactory.ExtractECDSASignature(signature.ToHex());
            return Bech32.Encode("io", 
                Hash.Hash160B(EthECKey.RecoverFromSignature(ecdaSignature, bytes).GetPubKey().Slice(1)));
        }

        public byte[] HashMessage(byte[] data)
        {
            var preamble = "\x16IoTeX Signed Message:\n" + data.Length;
            var preambleBytes = Encoding.ASCII.GetBytes(preamble);
            var message = new byte[preambleBytes.Length + data.Length];
            preambleBytes.CopyTo(message, 0);
            data.CopyTo(message, preambleBytes.Length);
            return Hash.Hash256B(message);
        }
    }
}