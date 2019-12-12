using System.Collections.Generic;
using System.Text;
using IoTeX.antenna.Accounts;
using IoTeX.antenna.JWT;
using Nethereum.Hex.HexConvertors.Extensions;
using Xunit;
using Xunit.Abstractions;

namespace IoTeX.antenna.Tests.JWT
{
    public class Ek256KTests
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public Ek256KTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void TestJwtSign()
        {
            var payload = new Dictionary<string, object>
            {
                {"iss", "044e18306ae9ef4ec9d07bf6e705442d4d1a75e6cdf750330ca2d880f2cc54607c9c33deb9eae9c06e06e04fe9ce3d43962cc67d5aa34fbeb71270d4bad3d648d9"},
                {"jti", "5d76d2e9ff7cf238522ef71e"},
                {"sub", "5b7a6d21dc6e35e14574d052"},
                {"exp", 1575844329},
                {"iat", 1568068329}
            };

            var signature = EK256K.Sign("0806c458b262edd333a191e92f561aff338211ee3e18ab315a074a2d82aa343f", payload);
            Assert.Equal(
                "eyJhbGciOiJFSzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiIwNDRlMTgzMDZhZTllZjRlYzlkMDdiZjZlNzA1NDQyZDRkMWE3NWU2Y2RmNzUwMzMwY2EyZDg4MGYyY2M1NDYwN2M5YzMzZGViOWVhZTljMDZlMDZlMDRmZTljZTNkNDM5NjJjYzY3ZDVhYTM0ZmJlYjcxMjcwZDRiYWQzZDY0OGQ5IiwianRpIjoiNWQ3NmQyZTlmZjdjZjIzODUyMmVmNzFlIiwic3ViIjoiNWI3YTZkMjFkYzZlMzVlMTQ1NzRkMDUyIiwiZXhwIjoxNTc1ODQ0MzI5LCJpYXQiOjE1NjgwNjgzMjl9.rC2Vh6J-Xk0N2iHTfzuthVdejQtD_HnV770eLAMBGGgS4YZfW7F_i4pR2FusINtlXxhss5XKYL-NFYCuh_2N0gA",
                signature);
        }
        
        [Fact]
        public void TestJwtVerify()
        {
            var payload = new Dictionary<string, object>
            {
                {"iss", "044e18306ae9ef4ec9d07bf6e705442d4d1a75e6cdf750330ca2d880f2cc54607c9c33deb9eae9c06e06e04fe9ce3d43962cc67d5aa34fbeb71270d4bad3d648d9"},
                {"jti", "5d76d2e9ff7cf238522ef71e"},
                {"sub", "5b7a6d21dc6e35e14574d052"},
                {"exp", 1575844329},
                {"iat", 1568068329}
            };

            var parsedPayload = EK256K.Verify("eyJhbGciOiJFSzI1NksiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiIwNDRlMTgzMDZhZTllZjRlYzlkMDdiZjZlNzA1NDQyZDRkMWE3NWU2Y2RmNzUwMzMwY2EyZDg4MGYyY2M1NDYwN2M5YzMzZGViOWVhZTljMDZlMDZlMDRmZTljZTNkNDM5NjJjYzY3ZDVhYTM0ZmJlYjcxMjcwZDRiYWQzZDY0OGQ5IiwianRpIjoiNWQ3NmQyZTlmZjdjZjIzODUyMmVmNzFlIiwic3ViIjoiNWI3YTZkMjFkYzZlMzVlMTQ1NzRkMDUyIiwiZXhwIjoxNTc1ODQ0MzI5LCJpYXQiOjE1NjgwNjgzMjl9.rC2Vh6J-Xk0N2iHTfzuthVdejQtD_HnV770eLAMBGGgS4YZfW7F_i4pR2FusINtlXxhss5XKYL-NFYCuh_2N0gA");
            Assert.Equal(payload["iss"], parsedPayload["iss"]);
        }
    }
}
