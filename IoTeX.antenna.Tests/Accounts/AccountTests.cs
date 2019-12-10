using System.Text;
using Nethereum.Hex.HexConvertors.Extensions;
using Xunit;
using Xunit.Abstractions;

namespace IoTeX.antenna.Tests.Accounts
{
    public class AccountTests
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public AccountTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void TestNewAccount()
        {
            var account = new antenna.Accounts.Account("0806c458b262edd333a191e92f561aff338211ee3e18ab315a074a2d82aa343f");

            Assert.Equal(
                "044e18306ae9ef4ec9d07bf6e705442d4d1a75e6cdf750330ca2d880f2cc54607c9c33deb9eae9c06e06e04fe9ce3d43962cc67d5aa34fbeb71270d4bad3d648d9",
                account.PublicKey);
            Assert.Equal(
                "io187wzp08vnhjjpkydnr97qlh8kh0dpkkytfam8j",
                account.Address);
        }

        [Fact]
        public void TestSign()
        {
            var account = antenna.Accounts.Account.FromPrivateKey("0806c458b262edd333a191e92f561aff338211ee3e18ab315a074a2d82aa343f");
            
            var signature = account.Sign(Encoding.ASCII.GetBytes("IoTeX is the auto-scalable and privacy-centric blockchain."));
            
            Assert.Equal(
                "99f4ef1005ae6c43548520e08dd11477e9ea59317087f9c6f33bc79eb701b14b043ff0d177bc419e585c0ecae42420fabb837e602c8a3578ea17dd1a8ed862e301",
                signature.ToHex());
        }
        
        [Fact]
        public void TestRecover()
        {
            var account = antenna.Accounts.Account.FromPrivateKey("0806c458b262edd333a191e92f561aff338211ee3e18ab315a074a2d82aa343f");
            
            var signature = account.Sign(Encoding.ASCII.GetBytes("IoTeX is the auto-scalable and privacy-centric blockchain."));

            var address = account.Recover("IoTeX is the auto-scalable and privacy-centric blockchain.", signature, false);
            
            Assert.Equal(account.Address,address);
        }
    }
}
