using Crypto;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Signer;
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

        private void Initialise(EthECKey key)
        {
            PrivateKey = key.GetPrivateKey();
            PublicKey = key.GetPubKey().ToHex();
            Address = Bech32.Encode("io", Hash.Hash160B(key.GetPubKey().Slice(1)));
        }

        public string Address { get; private set; }
        public string PrivateKey { get; private set; }
        public string PublicKey { get; private set; }
    }
}