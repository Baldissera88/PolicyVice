namespace PolicyVice
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Threading;

    public sealed class SyncResult
    {
        public int Enrollments, Started;
        public readonly List<string> Lines = new List<string>();
    }

    // Starts an MDM sync the way Windows does: by running the scheduled tasks that the enrollment client created
    // under \Microsoft\Windows\EnterpriseMgmt\<enrollment ID>\. "Schedule to run OMADMClient by client" is the task
    // that Sync under Access work or school starts; "Schedule #3 created by enrollment client" is the recurring
    // check-in task. The tasks run as SYSTEM, so starting them needs administrator rights.
    public static class MdmSync
    {
        public const string Folder = @"\Microsoft\Windows\EnterpriseMgmt\";
        public static readonly string[] Tasks = { "Schedule to run OMADMClient by client", "Schedule #3 created by enrollment client" };

        public static SyncResult Start(List<string> enrollmentIds)
        {
            SyncResult r = new SyncResult();
            foreach (string raw in enrollmentIds)
            {
                string id = (raw ?? "").Trim().Trim('{', '}');
                if (id.Length == 0) continue;
                r.Enrollments++;
                bool any = false;
                foreach (string task in Tasks)
                {
                    string output;
                    int code = Schtasks("/Run /TN \"" + Folder + id + "\\" + task + "\"", out output);
                    if (code == 0)
                    {
                        any = true;
                        r.Lines.Add("Started \"" + task + "\" for enrollment " + id + ".");
                    }
                    else r.Lines.Add("Could not start \"" + task + "\" for enrollment " + id + ": " + (output.Length > 0 ? output : "exit code " + code));
                }
                if (any) r.Started++;
            }
            return r;
        }

        // Demo mode: pretends to start the tasks.
        public static SyncResult Simulate(List<string> enrollmentIds)
        {
            Thread.Sleep(1200);
            SyncResult r = new SyncResult();
            foreach (string id in enrollmentIds)
            {
                r.Enrollments++;
                r.Started++;
                r.Lines.Add("Started \"" + Tasks[0] + "\" for enrollment " + id + " (demo).");
            }
            return r;
        }

        static int Schtasks(string args, out string output)
        {
            ProcessStartInfo psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (Process p = Process.Start(psi))
            {
                string err = "", o = "";
                Thread t = new Thread(delegate () { try { err = p.StandardError.ReadToEnd(); } catch (Exception) { } });
                t.IsBackground = true;
                t.Start();
                Thread t2 = new Thread(delegate () { try { o = p.StandardOutput.ReadToEnd(); } catch (Exception) { } });
                t2.IsBackground = true;
                t2.Start();
                if (!p.WaitForExit(30000))
                {
                    try { p.Kill(); } catch (Exception) { }
                    output = "schtasks.exe did not finish within 30 seconds.";
                    return -1;
                }
                t.Join(2000);
                t2.Join(2000);
                output = (err.Trim().Length > 0 ? err : o).Trim().Replace("\r", " ").Replace("\n", " ");
                return p.ExitCode;
            }
        }
    }
}
