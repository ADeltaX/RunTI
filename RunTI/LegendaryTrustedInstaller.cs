using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using static RunTI.NativeMethods;

//Readapted from https://github.com/Raymai97/SuperCMD

namespace RunTI
{
	class LegendaryTrustedInstaller
	{
		static STARTUPINFO SI;
		static PROCESSINFO PI;
		static SECURITY_ATTRIBUTES dummySA = new SECURITY_ATTRIBUTES();
		static IntPtr hProc, hToken, hDupToken, pEnvBlock;
        public static bool ForceTokenUseActiveSessionID;

        public static void RunWithTokenOf(
			string ProcessName,
			bool OfActiveSessionOnly,
			string ExeToRun, 
			string Arguments,
			string WorkingDir = "")
		{
			List<int> PIDs = new List<int>();
			foreach (Process p in Process.GetProcessesByName(
				Path.GetFileNameWithoutExtension(ProcessName)))
			{
				PIDs.Add(p.Id);
                break;
			}

			if (PIDs.Count == 0)
				return;

			RunWithTokenOf(PIDs[0], ExeToRun, Arguments, WorkingDir);
		}

		public static void RunWithTokenOf(
			int ProcessID,
			string ExeToRun,
			string Arguments,
			string WorkingDir = "")
		{
			try
			{
				#region Process ExeToRun, Arguments and WorkingDir

				// If ExeToRun is not absolute path, then let it be
				ExeToRun = Environment.ExpandEnvironmentVariables(ExeToRun);
				if (!ExeToRun.Contains("\\"))
				{
					foreach (string path in Environment.ExpandEnvironmentVariables("%path%").Split(';'))
					{
						string guess = path + "\\" + ExeToRun;
						if (File.Exists(guess)) { ExeToRun = guess; break; }
					}
				}
                if (!File.Exists(ExeToRun)) return;

				// If WorkingDir not exist, let it be the dir of ExeToRun
				// ExeToRun no dir? Impossible, as I would GoComplain() already
				WorkingDir = Environment.ExpandEnvironmentVariables(WorkingDir);
				if (!Directory.Exists(WorkingDir)) WorkingDir = Path.GetDirectoryName(ExeToRun);

				// If arguments exist, CmdLine must include ExeToRun as well
				Arguments = Environment.ExpandEnvironmentVariables(Arguments);
				string CmdLine = null;
				if (Arguments != "")
				{
					if (ExeToRun.Contains(" "))
						CmdLine = "\"" + ExeToRun + "\" " + Arguments;
					else
						CmdLine = ExeToRun + " " + Arguments;
				}

				#endregion

				// Set privileges of current process
				string privs = "SeDebugPrivilege";
				if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, out hToken))
                    return;

				foreach (string priv in privs.Split(','))
				{
                    if (!LookupPrivilegeValue("", priv, out LUID Luid))
                        return;

                    TOKEN_PRIVILEGES TP = new TOKEN_PRIVILEGES();
					TP.PrivilegeCount = 1;
					TP.Luid = Luid;
					TP.Attrs = SE_PRIVILEGE_ENABLED;
                    if (!(AdjustTokenPrivileges(hToken, false, ref TP, 0, IntPtr.Zero, IntPtr.Zero) & Marshal.GetLastWin32Error() == 0))
                        return;
				}
				CloseHandle(hToken);

				// Open process by PID
				hProc = OpenProcess(ProcessAccessFlags.All, false, ProcessID);
                if (hProc == null) return;

                // Open process token
                if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken)) return;

                // Duplicate to hDupToken
                if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, ref dummySA,
                    SecurityImpersonationLevel.SecurityIdentification,
                    TokenType.TokenPrimary, out hDupToken))
                    return;

				// Set session ID to make sure it shows in current user desktop
				// Only possible when SuperCMD running as SYSTEM!
                if (ForceTokenUseActiveSessionID)
                {
                    uint SID = WTSGetActiveConsoleSessionId();
                    if (!SetTokenInformation(hDupToken, TOKEN_INFORMATION_CLASS_TokenSessionId, ref SID, (uint)sizeof(uint)))
                        return;
                }

				// Create environment block
				if (!CreateEnvironmentBlock(out pEnvBlock, hToken, true))
                    return;

				// Create process with the token we "stole" ^^
				uint dwCreationFlags = (NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT);
				SI = new STARTUPINFO();
				SI.cb = Marshal.SizeOf(SI);
				SI.lpDesktop = "winsta0\\default";
				PI = new PROCESSINFO();

				// CreateProcessWithTokenW doesn't work in Safe Mode
				// CreateProcessAsUserW works, but if the Session ID is different,
				// we need to set it via SetTokenInformation()
				if (!CreateProcessWithTokenW(hDupToken, LogonFlags.WithProfile, ExeToRun, CmdLine,
					dwCreationFlags, pEnvBlock, WorkingDir, ref SI, out PI))
				{
					if (!CreateProcessAsUserW(hDupToken, ExeToRun, CmdLine, ref dummySA, ref dummySA,
						false, dwCreationFlags, pEnvBlock, WorkingDir, ref SI, out PI))
					{
                        return;
					}
				}
				CleanUp();
			}
			catch (Exception)
			{}
		}

		static void CleanUp()
		{
			CloseHandle(SI.hStdError);
            SI.hStdError = IntPtr.Zero;

			CloseHandle(SI.hStdInput);
            SI.hStdInput = IntPtr.Zero;

			CloseHandle(SI.hStdOutput);
            SI.hStdOutput = IntPtr.Zero;

			CloseHandle(PI.hThread);
            PI.hThread = IntPtr.Zero;

			CloseHandle(PI.hProcess);
            PI.hThread = IntPtr.Zero;

			DestroyEnvironmentBlock(pEnvBlock);
            pEnvBlock = IntPtr.Zero;

			CloseHandle(hDupToken);
            hDupToken = IntPtr.Zero;

			CloseHandle(hToken);
            hToken = IntPtr.Zero;
		}
	}
}
