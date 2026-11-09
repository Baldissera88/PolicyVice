namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Threading;
    using System.Windows.Forms;

    // Signs in to Microsoft Graph with a device code and reads the names of Intune apps, platform scripts and remediations.
    public sealed class SignInDialog : PageForm
    {
        public Dictionary<string, string> Names;
        public readonly List<string> Problems = new List<string>();

        readonly string tenant;
        readonly ManualResetEvent cancel = new ManualResetEvent(false);
        readonly SettingRow codeRow;
        readonly SettingRow statusRow;
        readonly FlatButton bOpen;
        DeviceCode code;

        public SignInDialog(Theme t, string tenant) : base("Get names from Intune", t)
        {
            this.tenant = tenant;
            Size = new System.Drawing.Size(Dpi.S(680), Dpi.S(520));
            bOpen = SmallButton("Copy code and open the sign-in page", delegate { OpenPage(); });
            bOpen.Enabled = false;
            codeRow = new SettingRow(Glyphs.Shield, "Getting a sign-in code…", "", new ButtonStrip(bOpen));
            statusRow = new SettingRow(Glyphs2.Clock, "Status", "Waiting for the sign-in service.", null);
            SettingRow about = new SettingRow(Glyphs.Info, "What this does",
                "PolicyVice signs in to Microsoft Graph read-only, with the Microsoft Graph Command Line Tools app (or the client ID set in Settings), and reads only the names of apps, platform scripts and remediations. " +
                "The names are saved on this computer for this tenant, so they show next time without signing in. The sign-in itself is not saved.", null);
            Add(new SectionTitle("Sign in"));
            Add(codeRow);
            Add(statusRow);
            Add(new SectionTitle("About"));
            Add(about);
            FormClosed += delegate { cancel.Set(); };
            Shown += delegate { Start(); };
        }

        void Start()
        {
            string clientId = Graph.ClientId;
            Thread th = new Thread(delegate ()
            {
                try
                {
                    DeviceCode d = Graph.Start(tenant, clientId);
                    Ui(delegate
                    {
                        code = d;
                        codeRow.Title = "Code: " + d.UserCode;
                        codeRow.Desc = "Open " + d.VerificationUri + ", enter the code and sign in with an account that can read Intune apps and scripts. The code works for " + (d.ExpiresIn / 60) + " minutes.";
                        bOpen.Enabled = true;
                        Show("Waiting for you to sign in…");
                    });
                    string token = Graph.Wait(tenant, clientId, d, cancel);
                    Ui(delegate { Show("Signed in. Reading the names of apps, platform scripts and remediations…"); });
                    List<string> problems = new List<string>();
                    Dictionary<string, string> found = Graph.ReadNames(token, problems, cancel);
                    Dictionary<string, string> merged = NameCache.Load(tenant);
                    foreach (KeyValuePair<string, string> kv in found) merged[kv.Key] = kv.Value;
                    if (found.Count > 0) NameCache.Save(tenant, merged);
                    Ui(delegate
                    {
                        Problems.AddRange(problems);
                        if (found.Count == 0)
                        {
                            Show("No names could be read." + (problems.Count > 0 ? " " + string.Join(" ", problems.ToArray()) : ""));
                            return;
                        }
                        Names = merged;
                        DialogResult = DialogResult.OK;
                        Close();
                    });
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    Ui(delegate { Show(ex.Message); });
                }
            });
            th.IsBackground = true;
            th.Start();
        }

        void Show(string text)
        {
            statusRow.Desc = text;
            Relayout();
        }

        void Ui(MethodInvoker a)
        {
            try
            {
                if (IsDisposed || cancel.WaitOne(0)) return;
                BeginInvoke((MethodInvoker)delegate
                {
                    try { a(); }
                    catch (Exception ex) { Safe.Report(ex); }
                });
            }
            catch (Exception) { }
        }

        void OpenPage()
        {
            if (code == null) return;
            try { Clipboard.SetText(code.UserCode); } catch (Exception) { }
            string url = code.VerificationUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? code.VerificationUri : "https://microsoft.com/devicelogin";
            try
            {
                // Through the signed-in user's shell, so the browser does not run as administrator.
                if (Program.IsAdmin) Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), "\"" + url + "\"");
                else Process.Start(url);
            }
            catch (Exception ex) { Show("The browser could not be opened: " + ex.Message + ". Open " + url + " yourself."); }
        }
    }
}
