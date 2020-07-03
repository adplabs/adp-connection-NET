using Microsoft.VisualStudio.TestTools.UnitTesting;
using ADPClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace ADPClient.Tests
{
    /// <summary>
    /// This will test using a real connection with the connection details defined in the ADPClientTestDemo project.
    /// This ensures the ClientCredentialConnection can be fetched from the Connection Factory, and then issue actual API / token requests.
    /// </summary>
    [TestClass()]
    public class ADPApiConnectionFactoryTests
    {
        private DateTime _testStartedAt;

        [TestMethod()]
        public void createConnection_getAccessToken3Times_Test()
        {
            this._testStartedAt = DateTime.Now;

            List<ADPAccessToken> generatedTokens = new List<ADPAccessToken>();

            for (int i = 0; i < 3; i++)
            {
                ClientCredentialConnection connection = null;

                using (StreamReader sr = new StreamReader("..\\..\\Content\\config\\default.json"))
                {
                    string clientconfig = sr.ReadToEnd();
                    ClientCredentialConfiguration connectionCfg = JSONUtil.Deserialize<ClientCredentialConfiguration>(clientconfig);
                    connection = (ClientCredentialConnection)ADPApiConnectionFactory.createConnection(connectionCfg);
                }

                connection.connect();
                if (connection.isConnectedIndicator())
                {
                    generatedTokens.Add(connection.accessToken);
                }
            }

            generatedTokens.ForEach(token =>
            {
                Assert.AreEqual("Bearer", token.TokenType);
                Assert.IsTrue(token.ExpiresIn > 0); // Assert it's more than 0 sec.
                Assert.AreEqual("api", token.Scope);
                Assert.IsNotNull(token.ExpiresOn);
                Assert.IsTrue(token.ExpiresOn > this._testStartedAt); // Should expire sometime after this test was executed.
            });
        }
    }
}