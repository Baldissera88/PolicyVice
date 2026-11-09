namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Text;
    using System.Threading;

    public sealed class DeviceCode
    {
        public string Code;
        public string UserCode;
        public string VerificationUri;
        public string Message;
        public int Interval = 5;
        public int ExpiresIn = 900;
    }

    public sealed class GraphException : Exception
    {
        public GraphException(string message) : base(message) { }
    }

    // Read-only Microsoft Graph sign-in with the device code flow, used only to look up names of Intune apps,
    // platform scripts and remediations. The token is kept in memory and never saved.
    public static class Graph
    {
        // Microsoft Graph Command Line Tools, the app Microsoft Graph PowerShell signs in with.
        public const string DefaultClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e";
        public const string Scopes = "https://graph.microsoft.com/DeviceManagementApps.Read.All https://graph.microsoft.com/DeviceManagementScripts.Read.All https://graph.microsoft.com/DeviceManagementConfiguration.Read.All";

        public static readonly string[,] Lists =
        {
            { "Apps", "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$select=id,displayName" },
            { "Platform scripts", "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?$select=id,displayName" },
            { "Remediations", "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?$select=id,displayName" },
        };

        public static string ClientId
        {
            get
            {
                string c = Prefs.Get("GraphClientId", null);
                return Names.IsGuid(c) ? c.Trim('{', '}') : DefaultClientId;
            }
        }

        static string Authority(string tenant)
        {
            return "https://login.microsoftonline.com/" + (Names.IsGuid(tenant) ? tenant.Trim('{', '}') : "organizations") + "/oauth2/v2.0/";
        }

        public static DeviceCode Start(string tenant, string clientId)
        {
            Dictionary<string, object> r = Post(Authority(tenant) + "devicecode", "client_id=" + Uri.EscapeDataString(clientId) + "&scope=" + Uri.EscapeDataString(Scopes + " offline_access"));
            string err = Str(r, "error_description") ?? Str(r, "error");
            if (err != null) throw new GraphException(err);
            DeviceCode d = new DeviceCode();
            d.Code = Str(r, "device_code");
            d.UserCode = Str(r, "user_code");
            d.VerificationUri = Str(r, "verification_uri") ?? "https://microsoft.com/devicelogin";
            d.Message = Str(r, "message");
            long? i = ImeJson.Long(ImeJson.Get(r, "interval"));
            long? e = ImeJson.Long(ImeJson.Get(r, "expires_in"));
            if (i.HasValue && i.Value > 0) d.Interval = (int)i.Value;
            if (e.HasValue && e.Value > 0) d.ExpiresIn = (int)e.Value;
            if (string.IsNullOrEmpty(d.Code) || string.IsNullOrEmpty(d.UserCode)) throw new GraphException("The sign-in service did not return a code.");
            return d;
        }

        // Waits until the user has signed in, and returns the access token.
        public static string Wait(string tenant, string clientId, DeviceCode d, WaitHandle cancel)
        {
            DateTime until = DateTime.UtcNow.AddSeconds(d.ExpiresIn);
            int interval = d.Interval;
            while (DateTime.UtcNow < until)
            {
                if (cancel.WaitOne(TimeSpan.FromSeconds(interval))) throw new OperationCanceledException();
                Dictionary<string, object> r = Post(Authority(tenant) + "token",
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=" + Uri.EscapeDataString(clientId) + "&device_code=" + Uri.EscapeDataString(d.Code));
                string token = Str(r, "access_token");
                if (!string.IsNullOrEmpty(token)) return token;
                string err = Str(r, "error");
                if (err == "authorization_pending") continue;
                if (err == "slow_down") { interval += 5; continue; }
                if (err == "expired_token") throw new GraphException("The code expired. Start again.");
                if (err == "authorization_declined" || err == "access_denied") throw new GraphException("The sign-in was declined.");
                throw new GraphException(Str(r, "error_description") ?? err ?? "The sign-in failed.");
            }
            throw new GraphException("The code expired. Start again.");
        }

        // Names by ID from the Intune lists. A list that cannot be read is reported and the others are still read.
        public static Dictionary<string, string> ReadNames(string token, List<string> problems, WaitHandle cancel)
        {
            Dictionary<string, string> names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < Lists.GetLength(0); i++)
            {
                string url = Lists[i, 1];
                int pages = 0;
                try
                {
                    while (!string.IsNullOrEmpty(url) && pages++ < 200)
                    {
                        if (cancel != null && cancel.WaitOne(0)) throw new OperationCanceledException();
                        Dictionary<string, object> r = Get(url, token);
                        string err = Error(r);
                        if (err != null) throw new GraphException(err);
                        List<object> value = ImeJson.Get(r, "value") as List<object>;
                        if (value != null)
                        {
                            foreach (object o in value)
                            {
                                Dictionary<string, object> item = o as Dictionary<string, object>;
                                string id = Str(item, "id"), name = Str(item, "displayName");
                                if (!string.IsNullOrEmpty(id) && !string.IsNullOrEmpty(name)) names[id.Trim('{', '}')] = name;
                            }
                        }
                        url = Str(r, "@odata.nextLink");
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    if (problems != null) problems.Add(Lists[i, 0] + ": " + ex.Message.Trim());
                }
            }
            return names;
        }

        static string Error(Dictionary<string, object> r)
        {
            Dictionary<string, object> e = ImeJson.Get(r, "error") as Dictionary<string, object>;
            if (e == null) return null;
            string code = Str(e, "code"), msg = Str(e, "message");
            if (code == "Forbidden" || code == "Authorization_RequestDenied" || (msg != null && msg.IndexOf("not authorized", StringComparison.OrdinalIgnoreCase) >= 0))
                return "access denied. The account or the app needs consent for " + Scopes.Replace("https://graph.microsoft.com/", "").Replace(" ", ", ") + ".";
            return msg ?? code ?? "failed";
        }

        static string Str(Dictionary<string, object> d, string key)
        {
            if (d == null) return null;
            object v = ImeJson.Get(d, key);
            return v == null ? null : Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture);
        }

        static HttpWebRequest Request(string url)
        {
            // .NET Framework 4.5 does not offer TLS 1.2 by default.
            try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072; } catch (Exception) { }
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Timeout = 60000;
            req.ReadWriteTimeout = 60000;
            req.UserAgent = "PolicyVice/" + Program.Version;
            try
            {
                req.Proxy = WebRequest.GetSystemWebProxy();
                req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            }
            catch (Exception) { }
            return req;
        }

        static Dictionary<string, object> Post(string url, string form)
        {
            HttpWebRequest req = Request(url);
            req.Method = "POST";
            req.ContentType = "application/x-www-form-urlencoded";
            byte[] body = Encoding.UTF8.GetBytes(form);
            req.ContentLength = body.Length;
            using (Stream s = req.GetRequestStream()) s.Write(body, 0, body.Length);
            return Send(req);
        }

        static Dictionary<string, object> Get(string url, string token)
        {
            HttpWebRequest req = Request(url);
            req.Method = "GET";
            req.Accept = "application/json";
            req.Headers[HttpRequestHeader.Authorization] = "Bearer " + token;
            return Send(req);
        }

        // Returns the JSON body also for error responses, which carry the error code.
        static Dictionary<string, object> Send(HttpWebRequest req)
        {
            HttpWebResponse resp;
            try { resp = (HttpWebResponse)req.GetResponse(); }
            catch (WebException ex)
            {
                resp = ex.Response as HttpWebResponse;
                if (resp == null) throw new GraphException("Could not reach " + req.RequestUri.Host + ": " + ex.Message);
            }
            using (resp)
            using (StreamReader r = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            {
                string text = r.ReadToEnd();
                Dictionary<string, object> d = ImeJson.Parse(text) as Dictionary<string, object>;
                if (d == null) throw new GraphException("Unexpected answer from " + req.RequestUri.Host + " (HTTP " + (int)resp.StatusCode + ").");
                return d;
            }
        }
    }
}
