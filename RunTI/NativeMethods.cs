using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Windows.Forms;

//Readapted from https://github.com/Raymai97/SuperCMD

namespace RunTI
{
    public class NativeMethods
	{
		[DllImport("user32.dll", SetLastError = true)]
		public static extern bool SetProcessDPIAware();

		[DllImport("shell32.dll", CharSet = CharSet.Auto)]
		public static extern uint ExtractIconEx(string szFileName, int nIconIndex,
		   IntPtr[] phiconLarge, IntPtr[] phiconSmall, uint nIcons);

        #region WIN32 API 

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        public static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            [MarshalAs(UnmanagedType.Struct)] ref TOKEN_PRIVILEGES NewState,
            uint dummy, IntPtr dummy2, IntPtr dummy3);

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            internal uint PrivilegeCount;
            internal LUID Luid;
            internal uint Attrs;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            internal int LowPart;
            internal uint HighPart;
        }

        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName,
            out LUID lpLuid);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
             ProcessAccessFlags dwDesiredAccess,
             bool bInheritHandle,
             int processId
        );

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle,
            uint DesiredAccess, out IntPtr TokenHandle);

        public const uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const uint STANDARD_RIGHTS_READ = 0x00020000;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_IMPERSONATE = 0x0004;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_QUERY_SOURCE = 0x0010;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_ADJUST_GROUPS = 0x0040;
        public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
        public const uint TOKEN_ADJUST_SESSIONID = 0x0100;
        public const uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean SetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass,
            ref uint TokenInformation, uint TokenInformationLength);

        public const uint TOKEN_INFORMATION_CLASS_TokenSessionId = 12;

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUserW(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESSINFO lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSINFO
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            LogonFlags dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESSINFO lpProcessInformation);

        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        public const uint NORMAL_PRIORITY_CLASS = 0x00000020;
        public const uint CREATE_NEW_CONSOLE = 0x00000010;
        public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            SecurityImpersonationLevel ImpersonationLevel,
            TokenType TokenType,
            out IntPtr phNewToken);

        public enum SecurityImpersonationLevel
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3
        }

        public enum TokenType
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        #endregion

        #region SendMessage API

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
		public static extern IntPtr SendMessage(IntPtr hWnd, int Msg, int wParam, IntPtr lParam);
		[DllImport("user32.dll", CharSet = CharSet.Auto)]
		public static extern int SendMessage(IntPtr hwnd, int wMsg, int wParam, ref COPYDATASTRUCT lParam);
		[DllImport("user32.dll")]
		public static extern bool InSendMessage();
		[DllImport("user32.dll")]
		public static extern bool ReplyMessage(IntPtr lResult);

		public const int WM_COPYDATA = 0x004A;

		[StructLayout(LayoutKind.Sequential)]
		public struct COPYDATASTRUCT
		{
			/// <summary>
			/// Pointer of sender (so receiver can send back)
			/// </summary>
			public IntPtr dwData;
			/// <summary>
			/// Count of Bytes
			/// </summary>
			public int cbData;
			/// <summary>
			/// Pointer of a byte array
			/// </summary>
			public IntPtr lpData;
		}

		public static void _SendMessage(string msg, IntPtr target)
		{
			byte[] b = Encoding.UTF8.GetBytes(msg);
			IntPtr hLog = Marshal.AllocHGlobal(b.Length);
			Marshal.Copy(b, 0, hLog, b.Length);
			COPYDATASTRUCT data = new COPYDATASTRUCT();
			data.cbData = b.Length;
			data.lpData = hLog;
			SendMessage(target, WM_COPYDATA, 0, ref data);
		}

		public static string _GetMessage(Message m)
		{
			string msg = null;
			if (m.Msg == NativeMethods.WM_COPYDATA)
			{
				if (InSendMessage()) ReplyMessage(IntPtr.Zero);
				COPYDATASTRUCT data = (COPYDATASTRUCT)m.GetLParam(typeof(COPYDATASTRUCT));
				byte[] b = new byte[data.cbData];
				Marshal.Copy(data.lpData, b, 0, data.cbData);
				msg = Encoding.UTF8.GetString(b);
			}
			return msg;
		}

		#endregion

		#region Set form's large and small icon explicitly
		
		const int WM_SETICON = 0x80;
		const int ICON_SMALL = 0;
		const int ICON_BIG = 1;

		public static void SetFormIcon(IntPtr hWnd, string IconPath, int IconIndex = 0)
		{
			uint IconCount = (uint)(IconIndex) + 1;
			IntPtr[] hSmallIcon = new IntPtr[IconCount];
			IntPtr[] hLargeIcon = new IntPtr[IconCount];
			ExtractIconEx(IconPath, IconIndex, hLargeIcon, hSmallIcon, IconCount);
			SendMessage(hWnd, WM_SETICON, ICON_BIG, hLargeIcon[IconIndex]);
			SendMessage(hWnd, WM_SETICON, ICON_SMALL, hSmallIcon[IconIndex]);
		}

		#endregion

		#region Start service even if it's disabled 

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

		[DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")]
		static extern int CloseServiceHandle(IntPtr hSCObject);

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		static extern Boolean ChangeServiceConfig(
			IntPtr hService,
			UInt32 nServiceType,
			SvcStartupType nStartType,
			UInt32 nErrorControl,
			String lpBinaryPathName,
			String lpLoadOrderGroup,
			IntPtr lpdwTagId,
			[In] char[] lpDependencies,
			String lpServiceStartName,
			String lpPassword,
			String lpDisplayName);

		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		static extern Boolean QueryServiceConfig(
			IntPtr hService, 
			IntPtr intPtrQueryConfig, 
			UInt32 cbBufSize, 
			out UInt32 pcbBytesNeeded);

		[DllImport("advapi32", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool StartService(
						IntPtr hService,
					int dwNumServiceArgs,
					string[] lpServiceArgVectors
					);

		const uint SC_MANAGER_CONNECT = 0x00000001;
		const uint SC_MANAGER_ALL_ACCESS = 0x000F003F;
		const uint SERVICE_QUERY_CONFIG = 0x00000001;
		const uint SERVICE_CHANGE_CONFIG = 0x00000002;
		const uint SERVICE_START = 0x00000016;
		const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;

		enum SvcStartupType : uint
		{
			BootStart = 0,      //Device driver started by the system loader.
			SystemStart = 1,    //Device driver started by the IoInitSystem function.
			Automatic = 2,
			Manual = 3,
			Disabled = 4
		}

		[StructLayout(LayoutKind.Sequential)]
		class QUERY_SERVICE_CONFIG
		{
			[MarshalAs(UnmanagedType.U4)]
			public UInt32 dwServiceType;
			[MarshalAs(UnmanagedType.U4)]
			public SvcStartupType dwStartType;
			[MarshalAs(UnmanagedType.U4)]
			public UInt32 dwErrorControl;
			[MarshalAs(UnmanagedType.LPWStr)]
			public String lpBinaryPathName;
			[MarshalAs(UnmanagedType.LPWStr)]
			public String lpLoadOrderGroup;
			[MarshalAs(UnmanagedType.U4)]
			public UInt32 dwTagID;
			[MarshalAs(UnmanagedType.LPWStr)]
			public String lpDependencies;
			[MarshalAs(UnmanagedType.LPWStr)]
			public String lpServiceStartName;
			[MarshalAs(UnmanagedType.LPWStr)]
			public String lpDisplayName;
		};

		public static bool TryStartService(string svcName)
		{
			bool wasDisabled = false;
			QUERY_SERVICE_CONFIG SvcConfig = new QUERY_SERVICE_CONFIG();
			IntPtr hSvcMgr = OpenSCManager(null, null, SC_MANAGER_CONNECT);
			IntPtr hSvc = OpenService(hSvcMgr, "TrustedInstaller",
				SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_START);
			// Check if the service was disabled
			uint dummy = 0;
			IntPtr ptr = Marshal.AllocHGlobal(4096);
			if (!QueryServiceConfig(hSvc, ptr, 4096, out dummy)) return false;
			Marshal.PtrToStructure(ptr, SvcConfig);
			Marshal.FreeHGlobal(ptr);
			wasDisabled = (SvcConfig.dwStartType == SvcStartupType.Disabled);
			// If it was disabled, set it as manual temporary
			if (wasDisabled)
			{
				if (!ChangeServiceConfig(hSvc, SERVICE_NO_CHANGE,
					SvcStartupType.Manual, SERVICE_NO_CHANGE, 
					null, null, IntPtr.Zero, null, null, null, null)) return false;
			}
			// Start the service
			StartService(hSvc, 0, null);
			// If it was disabled, set it back to disabled
			if (wasDisabled)
			{
				if (!ChangeServiceConfig(hSvc, SERVICE_NO_CHANGE,
					SvcStartupType.Disabled, SERVICE_NO_CHANGE,
					null, null, IntPtr.Zero, null, null, null, null)) return false;
			}
			// Clean up
			CloseServiceHandle(hSvc);
			CloseServiceHandle(hSvcMgr);
			return true;
		}

		#endregion
	}
}
