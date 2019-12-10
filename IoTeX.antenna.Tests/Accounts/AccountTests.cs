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
    }
}
