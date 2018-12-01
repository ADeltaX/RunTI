using System;
using System.Windows.Forms;
using System.IO;
using Microsoft.Win32;
using System.Diagnostics;
using System.Collections.Generic;

namespace RunTI
{
    static class Program
    {
        // Prevent idiots to touch this executable
        static readonly FileStream thisExec = new FileStream(Application.ExecutablePath, FileMode.Open, FileAccess.Read);

        [STAThread]
        static void Main(string[] args)
        {
#if UACB
            if (!(args.Length > 0))
            {
                Bypass();
                return;
            }
            else
            {
                //This exposes to 34987567834598345 bugs so don't use UACSkip pls
                List<string> b = new List<string>(args);

                var pos = b.IndexOf("/SwitchTI");
                if (pos == -1)
                    args = new string[0];
            }
#endif

            if (args.Length > 0 && args[0].ToLower() == "/switchti")
                ParseCmdLine(args);
            else
                LaunchWithParams(args);
        }

#if UACB
        static void Bypass()
        {
            Registry.CurrentUser.OpenSubKey("Environment", true).SetValue("windir", $"{Application.ExecutablePath} /bypass ", RegistryValueKind.String);

            var si = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                UseShellExecute = false,
                Arguments = @"/RUN /TN Microsoft\Windows\DiskCleanup\SilentCleanup /I"
            };

            var p = Process.Start(si);
            p.WaitForExit();

            Registry.CurrentUser.OpenSubKey("Environment", true).DeleteValue("windir");
        }
#endif

        static void LaunchWithParams(string[] args)
        {
            var exe = "cmd.exe";
            var arguments = "";
            var dirPath = "";

            if (args.Length > 0)
            {
                if (args[0].ToLower().StartsWith("/wd:"))
                    dirPath = args[0].Replace("/wd:", "");
                else if (args[0].Replace("\"", "").ToLower().EndsWith(".bat") || args[0].Replace("\"", "").ToLower().EndsWith(".cmd"))
                    arguments = "/c " + args[0];
                else if (args[0].Replace("\"", "").ToLower().EndsWith(".lnk")) //I'm sure at 101% there are better ways.
                    arguments = "/c start " + args[0];
                else if (args[0].Replace("\"", "").ToLower().EndsWith(".exe"))
                {
                    exe = args[0];
                    foreach (string arg in args)
                        arguments += arguments + " ";

                    arguments.Trim();
                }
            }

            if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath.Replace("\"", "")))
            {
                try
                {
                    dirPath = Environment.CurrentDirectory;
                }
                catch (Exception)
                {
                    dirPath = "";
                }
            }


            if (StartTiService())
            {
                LegendaryTrustedInstaller.RunWithTokenOf("winlogon.exe", true,
                    Application.ExecutablePath,
                    $" /SwitchTI /Dir:\"{dirPath.Replace("\"", "")}\" /Run:\"{exe}\" {arguments}"); //ARGUMENTS
            }
        }

        static void ParseCmdLine(string[] args)
        {
            string ExeToRun = "", Arguments = "", WorkingDir = "", toRun = "";

            // args[] can't process DirPath and ExeToRun containing '\'
            // and that will influence the other argument too :(
            // so I need to do it myself :/
            string CmdLine = Environment.CommandLine;
            int iToRun = CmdLine.ToLower().IndexOf("/run:");
            if (iToRun != -1)
            {
                toRun = CmdLine.Substring(iToRun + 5).Trim();
                // Process toRun
                int iDQuote1, iDQuote2;
                iDQuote1 = toRun.IndexOf("\"");
                // If a pair of double quote is exist
                if (iDQuote1 != -1)
                {
                    toRun = toRun.Substring(iDQuote1 + 1);
                    iDQuote2 = toRun.IndexOf("\"");
                    if (iDQuote2 != -1)
                    {
                        // before 2nd double quote is ExeToRun, after is Arguments
                        ExeToRun = toRun.Substring(0, iDQuote2);
                        Arguments = toRun.Substring(iDQuote2 + 1);
                    }
                }
                else
                {
                    // before 1st Space is ExeToRun, after is Arguments
                    int firstSpace = toRun.IndexOf(" ");
                    if (firstSpace == -1) { ExeToRun = toRun; }
                    else
                    {
                        ExeToRun = toRun.Substring(0, firstSpace);
                        Arguments = toRun.Substring(firstSpace + 1);
                    }
                }
            }

            // Process all optional arguments before toRun, '/' as separator
            if (iToRun != -1)
                CmdLine = CmdLine.Substring(0, iToRun) + "/";

            string cmdline = CmdLine.ToLower();

            string tmp;

            int iDir, iNextSlash;

            iDir = cmdline.IndexOf("/dir:");
            if (iDir != -1)
            {
                tmp = CmdLine.Substring(iDir + 5);
                iNextSlash = tmp.IndexOf("/");
                if (iNextSlash != -1)
                {
                    tmp = tmp.Substring(0, iNextSlash);
                    WorkingDir = tmp.Replace("\"", "").Trim();
                }
            }

            LegendaryTrustedInstaller.ForceTokenUseActiveSessionID = true;
            LegendaryTrustedInstaller.RunWithTokenOf("TrustedInstaller.exe", false,
                ExeToRun, Arguments, WorkingDir);
        }

        public static bool StartTiService()
        {
            try
            {
                NativeMethods.TryStartService("TrustedInstaller");
                return true;
            }
            catch (Exception)
            {
                //hmm....
                return false;
            }
        }
    }
}
