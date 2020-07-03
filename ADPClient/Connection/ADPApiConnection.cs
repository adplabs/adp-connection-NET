/*# This file is part of adp-api-library.
# https://github.com/adplabs/adp-connection-NET

# Copyright © 2015-2016 ADP, LLC.

# Licensed under the Apache License, Version 2.0 (the “License”);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an “AS IS” BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.  See the License for the specific language
# governing permissions and limitations under the License.
*/
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Net.Http;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Web.Script.Serialization;
using ADPClient.ADPException;

namespace ADPClient
{

    /// <summary>
    /// 
    /// </summary>
    public abstract class ADPApiConnection
    {
        /// <summary>
        /// See https://docs.microsoft.com/en-us/dotnet/api/system.net.http.httpclient?view=netframework-4.5
        /// </summary>
        private static HttpClient _httpClient = null;

        /// <summary>
        /// 
        /// </summary>
        public ConnectionConfiguration connectionConfiguration { get; set; }

        /// <summary>
        /// 
        /// </summary>
        protected int tokenExpiration { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public string state { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public ADPAccessToken accessToken { get; set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="connectionConfiguration"></param>
        public ADPApiConnection(ConnectionConfiguration connectionConfiguration)
        {
            this.connectionConfiguration = connectionConfiguration;
        }

        /// <summary>
        /// 
        /// </summary>
        public void connect()
        {
            if (connectionConfiguration == null)
            {
                throw new ADPConnectionException("Configuration not provided.");
            }

            this.accessToken = this.getAccessToken();
        }

        /// <summary>
        /// 
        /// </summary>
        public void disconnect()
        {
            this.accessToken = null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public virtual bool isConnectedIndicator()
        {
            if (accessToken != null)
            {
                // we have a valid token so check if it expired
                if (DateTime.Compare(DateTime.Now, accessToken.ExpiresOn.Value) > 0)
                {
                    // token expires so set to null
                    accessToken = null;
                }
            }

            return accessToken != null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>valid ADPAccessToken</returns>
        protected virtual ADPAccessToken getAccessToken()
        {
            ADPAccessToken token = accessToken;
            Dictionary<string, string> data = null;
            AuthenticationHeaderValue credentials = null;

            if (!isConnectedIndicator())
            {
                if (String.IsNullOrEmpty(connectionConfiguration.grantType))
                {
                    throw new ADPConnectionException("ADP Connection Exception: config option grantType cannot be null/empty");
                }

                if (String.IsNullOrEmpty(connectionConfiguration.tokenServerURL))
                {
                    throw new ADPConnectionException("ADP Connection Exception: config option tokenServerURL cannot be null/empty");
                }

                data = new Dictionary<string, string>();

                data.Add("client_id", connectionConfiguration.clientID);
                data.Add("client_secret", connectionConfiguration.clientSecret);
                data.Add("grant_type", connectionConfiguration.grantType);

                // send the data to ADP server/s
                var result = SendWebRequest(connectionConfiguration.tokenServerURL, data, credentials);

                if (!String.IsNullOrEmpty(result))
                {
                    token = JSONUtil.Deserialize<ADPAccessToken>(result);
                }
            }

            // if valid token from session or 
            // token not expired return it.
            return token;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ADPProductURL"></param>
        /// <returns></returns>
        public virtual string getADPData(string ADPProductURL)
        {
            string serverResponse = null;
            ADPAccessToken token = getAccessToken();
            Dictionary<string, string> data = null;

            if (isConnectedIndicator() && (token != null))
            {
                // send the data to ADP server/s
                // since we have a valid token
                serverResponse = SendWebRequest(connectionConfiguration.apiRequestURL + ADPProductURL, data, new AuthenticationHeaderValue(token.TokenType, token.AccessToken), "application/json", "GET");
            }
            else
            {
                throw new ADPConnectionException("Connection Exception: connection not established.");
            }
            return serverResponse;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ADPProductURL"></param>
        /// <param name="body"></param>
        /// <returns></returns>
        public virtual string postADPEvent(string ADPProductURL, string body)
        {
            string serverResponse = null;
            ADPAccessToken token = getAccessToken();
            Dictionary<string, string> data = null;

            if (isConnectedIndicator() && (token != null))
            {
                // send the data to ADP server/s
                // since we have a valid token
                serverResponse = SendWebRequest(connectionConfiguration.apiRequestURL + ADPProductURL, data, new AuthenticationHeaderValue(token.TokenType, token.AccessToken), "application/json", "POST", body);
            }
            else
            {
                throw new ADPConnectionException("Connection Exception: connection not established.");
            }
            return serverResponse;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="type"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        static byte[] PEM(string type, byte[] data)
        {
            string pem = Encoding.ASCII.GetString(data);
            string header = String.Format("-----BEGIN {0}-----", type);
            string footer = String.Format("-----END {0}-----", type);
            int start = pem.IndexOf(header) + header.Length;
            int end = pem.IndexOf(footer, start);
            string base64 = pem.Substring(start, (end - start));
            return Convert.FromBase64String(base64);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="Filename"></param>
        /// <param name="SSLKeyPath"></param>
        /// <param name="Password"></param>
        /// <returns></returns>
        private X509Certificate2 LoadCertificateFile(string Filename, string SSLKeyPath, string Password = null)
        {
            string certificatepath = Filename;
            X509Certificate2 x509 = null;

            if (!File.Exists(certificatepath))
            {
                certificatepath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + @"\" + Filename;
                if (!File.Exists(certificatepath))
                {
                    throw new ADPConnectionException("ADP connection Exception: File not found", String.Format("Tried: \r\n\t{0}\r\n\t{1}", Filename, certificatepath));
                }
            }

            try
            {
                if (certificatepath.EndsWith(".pfx"))
                {
                    x509 = new X509Certificate2(certificatepath, Password);
                }
                else
                {
                    using (FileStream fs = File.OpenRead(certificatepath))
                    {
                        byte[] data = new byte[fs.Length];
                        fs.Read(data, 0, data.Length);
                        if (data[0] != 0x30)
                        {
                            // maybe it's ASCII PEM base64 encoded ? 
                            data = PEM("CERTIFICATE", data);
                        }
                        if (data != null)
                            x509 = new X509Certificate2(data);
                    }
                }
            }
            catch (Exception e)
            {
                throw new ADPConnectionException("ADP connection Exception: Certificate processing error", e);
            }
            return x509;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        /// <param name="data"></param>
        /// <param name="authentication"></param>
        /// <param name="contentType"></param>
        /// <param name="method"></param>
        /// <param name="jsonBody"></param>
        /// <returns></returns>
        protected string SendWebRequest(string url, Dictionary<string, string> data, AuthenticationHeaderValue authentication = null, string contentType = "application/x-www-form-urlencoded", string method = "POST", string jsonBody = "")
        {
            string responseString = null;
            FormUrlEncodedContent content = null;
            System.Net.Http.HttpResponseMessage response = null;
           
            HttpClient client = GetStaticHttpClient();

            // iat needs to support Basic Authentication
            // uncomment this when it does.

            if (authentication != null)
            {
                client.DefaultRequestHeaders.Authorization = authentication;
            }

            client.DefaultRequestHeaders.Add("User-Agent", "adp-connection-net/1.0.1");
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(contentType));

            if (method.ToUpper().Equals("POST"))
            {
                if (jsonBody != String.Empty)
                {
                    var jsonContent = new StringContent(jsonBody, Encoding.UTF8, "application/json");
                    response = client.PostAsync(url, jsonContent).Result;
                }
                else if (data != null)
                {
                    content = new FormUrlEncodedContent(data);
                    response = client.PostAsync(url, content).Result;
                }


            }
            else
            {
                response = client.GetAsync(url).Result;
            }

            if (response.IsSuccessStatusCode)
            {
                // by calling .Result you are performing a synchronous call
                var responseContent = response.Content;

                // by calling .Result you are synchronously reading the result
                responseString = responseContent.ReadAsStringAsync().Result;
            }
            else
            {
                // by calling .Result you are performing a synchronous call
                var responseContent = response.Content;

                // by calling .Result you are synchronously reading the result
                responseString = responseContent.ReadAsStringAsync().Result;
                throw new ADPConnectionException(String.Format("Connection Exception: {0}: {1}", response.StatusCode, responseString), new JavaScriptSerializer().Serialize(response));
            }


            return responseString;
        }

        /// <summary>
        /// Get instantiated HttpClient to perform ADP API requests.
        /// 
        /// 
        /// See https://docs.microsoft.com/en-us/dotnet/api/system.net.http.httpclient?view=netframework-4.5
        /// "HttpClient is intended to be instantiated once and re-used throughout the life of an application."
        /// </summary>
        /// <param name="handler"></param>
        /// <returns></returns>
        private HttpClient GetStaticHttpClient()
        {
            if (_httpClient == null)
            {
                string certpath = (HttpContext.Current == null) ? connectionConfiguration.sslCertPath : HttpContext.Current.Server.MapPath(connectionConfiguration.sslCertPath);

                WebRequestHandler handler = new WebRequestHandler();
                X509Certificate2 certificate = LoadCertificateFile(certpath, connectionConfiguration.sslKeyPath, connectionConfiguration.sslKeyPass);
                handler.ClientCertificates.Add(certificate);

                _httpClient = new HttpClient(handler);
            }

            return _httpClient;           
        }
    }
}

