using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;

namespace PKMk2
{
    class Program
    {
        //--------------------------
        //**Imported functions begin

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, int dwThreadId);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 CloseHandle(IntPtr hProcess);
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass, IntPtr threadInformation, int threadInformationLength, IntPtr returnLengthPtr);
        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess,
        IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, int flNewProtect, out int lpflOldProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
        [DllImport("kernel32.dll")]
        static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);
        [DllImport("user32.dll", SetLastError = true)]
        internal static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
        [DllImport("user32.dll")]
        static extern bool BlockInput(bool fBlockIt);
        [DllImport("user32.dll")]
        static extern bool SwapMouseButton(bool fSwap);

        public enum ProcessAccessFlags : int
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
        public enum ThreadAccessFlags : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }
        public enum AllocationProtect : int
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }
        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int lType;
        }

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }
        const int MEM_COMMIT = 0x00001000;
        public delegate void CommandFunctionA(string input);
        public delegate void CommandFunctionN();

        //**Imported functions end
        //------------------------

        public static void Main(string[] args)
        {
            while (1 == 1)
            {
                InputCommand();
                Console.WriteLine();
            }
        }
        public static void randBytes(byte[] byteArr)
        {
            Random rand = new Random();
            for (int i = 0; i < byteArr.Length; i++)
            {
                byteArr[i] = (byte)rand.Next(0, 256);
            }
        }
        public static void ThreadAttackProc(string procName)
        {
            Process proc = Process.GetProcessesByName(procName)[0];
            ProcessThreadCollection procThreads = proc.Threads;
            IntPtr mainAddr = (IntPtr)0;
            foreach (ProcessThread procThread in procThreads)
            {
                if ((int)procThread.StartAddress != 0)
                {
                    mainAddr = procThread.StartAddress;
                }
            }
            IntPtr procHandle = OpenProcess((int)ProcessAccessFlags.All, false, proc.Id);
            Console.WriteLine(Convert.ToString((int)procHandle, 16));
            byte[] buffer = new byte[1000];
            //randBytes(buffer);
            int rBytes = 0;
            ReadProcessMemory((int)procHandle, (int)mainAddr, buffer, buffer.Length, ref rBytes);
            string outStr = Convert.ToString(buffer[0], 16);
            for (int i = 1; i < buffer.Length; i++)
            {
                outStr += " " + Convert.ToString(buffer[i], 16);
            }
            Console.WriteLine(outStr);
            /*int wBytes = 0;
            bool wSuccess = WriteProcessMemory(procHandle, (int)mainAddr - 5000, buffer, buffer.Length, ref wBytes);
            Console.WriteLine(wSuccess);*/
            Console.WriteLine(Marshal.GetLastWin32Error());
            Console.ReadKey(true);
        }
        public static void FreezeThreads(string procName)
        {
            if (Process.GetProcessesByName(procName).Length == 0)
            {
                Console.WriteLine("Invalid process name");
                return;
            }
            Process proc = Process.GetProcessesByName(procName)[0];
            foreach (ProcessThread procThread in proc.Threads)
            {
                IntPtr hThread = OpenThread((int)ThreadAccessFlags.SUSPEND_RESUME, false, procThread.Id);
                SuspendThread(hThread);
            }
        }
        public static void ResumeThreads(string procName)
        {
            if (Process.GetProcessesByName(procName).Length == 0)
            {
                Console.WriteLine("Invalid process name");
                return;
            }
            Process proc = Process.GetProcessesByName(procName)[0];
            foreach (ProcessThread procThread in proc.Threads)
            {
                IntPtr hThread = OpenThread((int)ThreadAccessFlags.SUSPEND_RESUME, false, procThread.Id);
                ResumeThread(hThread);
            }
        }
        public static void TerminateThreads(string procName)
        {
            if (Process.GetProcessesByName(procName).Length == 0)
            {
                Console.WriteLine("Invalid process name");
                return;
            }
            Process proc = Process.GetProcessesByName(procName)[0];
            foreach (ProcessThread procThread in proc.Threads)
            {
                IntPtr hThread = OpenThread((int)ThreadAccessFlags.TERMINATE, false, procThread.Id);
                TerminateThread(hThread, 0);
            }
        }
        public static void TerminateProcess(string procName)
        {
            if (Process.GetProcessesByName(procName).Length == 0)
            {
                Console.WriteLine("Invalid process name");
                return;
            }
            Process proc = Process.GetProcessesByName(procName)[0];
            IntPtr procHandle = OpenProcess((int)ProcessAccessFlags.All, false, proc.Id);
            TerminateProcess(procHandle, 0);
        }
        public static void ThreadInfo(string procName)
        {
            if (Process.GetProcessesByName(procName).Length == 0)
            {
                Console.WriteLine("Invalid process name");
                return;
            }
            Process proc = Process.GetProcessesByName(procName)[0];
            foreach (ProcessThread thread in proc.Threads)
            {
                Console.WriteLine(thread.ThreadState);
            }
        }
        public static void ListProcesses()
        {
            Process[] localProcs = Process.GetProcesses();
            foreach (Process localProc in localProcs)
            {
                Console.WriteLine(localProc.ProcessName);
            }
        }
        public static void PrintLastError()
        {
            Console.WriteLine(Marshal.GetLastWin32Error());
        }
        public static void ReplaceZeroBytes(byte[] arr)
        {
            Random rand = new Random();
            for (int i = 0; i < arr.Length; i++)
            {
                //if (arr[i] == 0){
                arr[i] = (byte)rand.Next(0, 256);
                //}
            }
        }
        public static bool WriteMemory(Process proc, byte[] buffer, int addr)
        {
            IntPtr procRef = OpenProcess((int)ProcessAccessFlags.All, false, proc.Id);
            if ((int)procRef == 0)
            {
                return false;
            }
            int bytesWritten = 0;
            bool WriteSuccess = WriteProcessMemory((int)procRef, addr, buffer, buffer.Length, ref bytesWritten);
            CloseHandle(procRef);
            return WriteSuccess;
        }
        public static bool ReadMemory(Process proc, byte[] buffer, int addr)
        {
            IntPtr procRef = OpenProcess((int)ProcessAccessFlags.VirtualMemoryRead, false, proc.Id);
            if ((int)procRef == 0)
            {
                return false;
            }
            int bytesWritten = 0;
            bool ReadSuccess = ReadProcessMemory((int)procRef, addr, buffer, buffer.Length, ref bytesWritten);
            CloseHandle(procRef);
            return ReadSuccess;
        }
        public static bool TamperMemory(Process proc, IntPtr addr, int size)
        {
            byte[] buffer = new Byte[size];
            ReplaceZeroBytes(buffer);
            bool w = WriteMemory(proc, buffer, (int)addr);
            return w;
        }
        public static string HexByteString(byte[] byteArr)
        {
            string byteString = Convert.ToString(byteArr[0], 16);
            for (int i = 1; i < byteArr.Length; i++)
            {
                byteString += " " + Convert.ToString(byteArr[i], 16);
            }
            return byteString;
        }
        public static void FreezeThreads(Process proc)
        {
            ProcessThreadCollection threads = proc.Threads;
            foreach (ProcessThread thread in threads)
            {
                IntPtr threadHandle = OpenThread((int)ThreadAccessFlags.SUSPEND_RESUME, false, thread.Id);
                if ((int)threadHandle == 0)
                {
                    return;
                }
                SuspendThread(threadHandle);
                CloseHandle(threadHandle);
            }
        }
        public static void UnfreezeThreads(Process proc)
        {
            ProcessThreadCollection threads = proc.Threads;
            foreach (ProcessThread thread in threads)
            {
                IntPtr threadHandle = OpenThread((int)ThreadAccessFlags.SUSPEND_RESUME, false, thread.Id);
                if ((int)threadHandle == 0)
                {
                    return;
                }
                ResumeThread(threadHandle);
                CloseHandle(threadHandle);
            }
        }
        static IntPtr GetThreadStartAddress(int threadId)
        {
            var hThread = OpenThread((int)ThreadAccessFlags.QUERY_INFORMATION, false, threadId);
            if (hThread == IntPtr.Zero)
                throw new Win32Exception();
            var buf = Marshal.AllocHGlobal(IntPtr.Size);
            try
            {
                var result = NtQueryInformationThread(hThread, 9, buf, IntPtr.Size, IntPtr.Zero);
                if (result != 0)
                    throw new Win32Exception(string.Format("NtQueryInformationThread failed; NTSTATUS = {0:X8}", result));
                return Marshal.ReadIntPtr(buf);
            }
            finally
            {
                CloseHandle(hThread);
                Marshal.FreeHGlobal(buf);
            }
        }
        static void OverwriteProcessThreads(Process proc, int size)
        {
            foreach (ProcessThread procThread in proc.Threads)
            {
                Console.WriteLine(TamperMemory(proc, GetThreadStartAddress(procThread.Id), size));
                Console.WriteLine(Marshal.GetLastWin32Error());
            }

        }
        static void PrintThreadAddresses(Process proc)
        {
            foreach (ProcessThread procThread in proc.Threads)
            {
                Console.WriteLine(Convert.ToString((int)GetThreadStartAddress(procThread.Id), 16));
            }
        }
        static void OverwriteProcMemory(Process proc)
        {
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            GetSystemInfo(out sysInfo);
            long minAddr = (long)sysInfo.minimumApplicationAddress;
            long startMinAddr = minAddr;
            long maxAddr = (long)sysInfo.maximumApplicationAddress;
            IntPtr procHandle = OpenProcess((int)ProcessAccessFlags.All, false, proc.Id);
            if ((int)procHandle == 0)
            {
                return;
            }
            MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
            while (minAddr < maxAddr)
            {
                VirtualQueryEx(procHandle, (IntPtr)minAddr, out memInfo, 28);
                if (memInfo.Protect == (int)AllocationProtect.PAGE_READWRITE || memInfo.Protect == (int)AllocationProtect.PAGE_EXECUTE_READWRITE && memInfo.State == MEM_COMMIT)
                {
                    TamperMemory(proc, (IntPtr)minAddr, memInfo.RegionSize);
                    //Console.WriteLine(Convert.ToString(minAddr, 16));
                    //Console.WriteLine(memInfo.RegionSize);
                }
                minAddr = minAddr + memInfo.RegionSize;
            }
            CloseHandle(procHandle);
        }
        static void RPKPayloadBegin()
        {
            System.Timers.Timer killTimer = new System.Timers.Timer();
            killTimer.AutoReset = false;
            killTimer.Interval = new Random().Next(100, 1000);
            killTimer.Elapsed += RPKPayloadBody;
            killTimer.Enabled = true;
        }
        static void RPKPayloadBody(Object source, System.Timers.ElapsedEventArgs e)
        {
            Process[] procList = Process.GetProcesses();
            bool isValid = false;
            Process proc = new Process();
            IntPtr procHandle;
            while (isValid == false)
            {
                proc = procList[new Random().Next(0, procList.Length - 1)];
                procHandle = OpenProcess((int)ProcessAccessFlags.All, false, proc.Id);
                if ((int)procHandle != 0 && proc.ProcessName != Process.GetCurrentProcess().ProcessName)
                {
                    isValid = true;
                    break;
                }
            }
            Console.WriteLine(proc.ProcessName);
            //OverwriteProcMemory(proc);
            RPKPayloadBegin();
        }
        static void SpecificProcKill(string procName)
        {
            if (Process.GetProcessesByName(procName).Length == 0)
            {
                Console.WriteLine("Invalid process name");
                return;
            }
            Process proc = Process.GetProcessesByName(procName)[0];
            FreezeThreads(proc);
            OverwriteProcMemory(proc);
            UnfreezeThreads(proc);
        }
        static void RandomProcKill()
        {
            Console.WriteLine("Execute?");
            ConsoleKeyInfo res = Console.ReadKey(true);
            if (res.Key == ConsoleKey.Y) RPKPayloadBegin();
            else Console.WriteLine("Okay bye");
            Console.ReadKey(true);
        }
        public static byte[] subByteArray(byte[] bArr, int indexS, int indexE)
        {
            byte[] sArr = new byte[indexE - indexS + 1];
            for (int i = indexE; i <= indexS; i++)
            {
                sArr[i - indexS] = bArr[i];
            }
            return sArr;
        }
        public static void ExitFunction()
        {
            Environment.Exit(0);
        }

        public static void ShakeWindow(string input)
        {
            IntPtr windowHandle = (IntPtr)0;
            Process[] procArray = Process.GetProcessesByName(input);
            if (procArray.Length > 0)
            {
                foreach (Process proc in procArray)
                {
                    if ((int)proc.MainWindowHandle != 0)
                    {
                        windowHandle = proc.MainWindowHandle;
                        break;
                    }
                }
            }
            else
            {
                Console.WriteLine("Process does not exist");
                return;
            }
            if ((int)windowHandle == 0)
            {
                Console.WriteLine("Process has no window");
                return;
            }
            System.Timers.Timer shakeTimer = new System.Timers.Timer(100);
            shakeTimer.Enabled = true;
            shakeTimer.Elapsed += (sender, e) => RandomWindowPos(sender, e, windowHandle);
        }

        public static void RandomWindowPos(object sender, System.Timers.ElapsedEventArgs e, IntPtr handle)
        {
            Rectangle bounds = Screen.PrimaryScreen.Bounds;
            int mH = bounds.Height;
            int mW = bounds.Width;
            Random r = new Random();
            int w = r.Next(1, mW);
            int h = r.Next(1, mH);
            int wPos = r.Next(0, mW - w);
            int hPos = r.Next(0, mH - h);
            MoveWindow(handle, wPos, hPos, w, h, true);
        }

        public static void BlockInputCmd()
        {
            BlockInput(true);
        }
        static bool buttonsSwapped = false;
        public static void SwapButtonsCmd()
        {
            SwapButtons(null,null);
        }
        public static void SwapButtons(Object sender, System.Timers.ElapsedEventArgs e)
        {
            System.Timers.Timer swapTimer = new System.Timers.Timer();
            swapTimer.AutoReset = false;
            swapTimer.Interval = new Random().Next(1, 1000);
            swapTimer.Enabled = true;
            swapTimer.Elapsed += SwapButtons;
            SwapMouseButton(!buttonsSwapped);
            buttonsSwapped = !buttonsSwapped;
        }

        public static void Beeps()
        {
            BeginBeep(null, null);
        }
        public static void BeginBeep(Object sender, System.Timers.ElapsedEventArgs e)
        {
            int t = new Random().Next(1, 100);
            int f = new Random().Next(440, 1760);
            System.Timers.Timer beepTimer = new System.Timers.Timer(t);
            beepTimer.AutoReset = false;
            beepTimer.Enabled = true;
            beepTimer.Elapsed += BeginBeep;
            Console.Beep(f, t);
        }
        public static void BeepSwapInit()
        {
            BeepSwap(null, null);
        }
        public static void BeepSwap(Object sender, System.Timers.ElapsedEventArgs e)
        {
            int t = new Random().Next(1000, 10000);
            int f = new Random().Next(220, 3520);
            System.Timers.Timer beepSwapTimer = new System.Timers.Timer(t);
            beepSwapTimer.AutoReset = false;
            beepSwapTimer.Enabled = true;
            beepSwapTimer.Elapsed += BeepSwap;
            Console.Beep(f, t);
            SwapMouseButton(!buttonsSwapped);
            buttonsSwapped = !buttonsSwapped;
        }

        public static void InputCommand()
        {


            CommandA[] CommandAList = new CommandA[]{
                new CommandA("freeze", FreezeThreads),
                new CommandA("resume", ResumeThreads),
                new CommandA("threadterm", TerminateThreads),
                new CommandA("procterm", TerminateProcess),
                new CommandA("threadinfo", ThreadInfo),
                new CommandA("memkill", SpecificProcKill),
                new CommandA("shake", ShakeWindow)
            };
            CommandN[] CommandNList = new CommandN[]{
                new CommandN("listproc", ListProcesses),
                new CommandN("memkillrandom", RandomProcKill),
                new CommandN("lasterror", PrintLastError),
                new CommandN("exit", ExitFunction),
                new CommandN("blockinput", BlockInputCmd),
                new CommandN("swapbuttons", SwapButtonsCmd),
                new CommandN("beep", Beeps),
                new CommandN("beepswap", BeepSwapInit)};
            string input = Console.ReadLine();
            bool cmdFound = false;

            if (input == "cmds")
            {
                Console.WriteLine("Commands with args:");
                foreach (CommandA com in CommandAList)
                {
                    Console.WriteLine(com.Name);
                }
                Console.WriteLine();
                Console.WriteLine("Commands without args:");
                foreach (CommandN com in CommandNList)
                {
                    Console.WriteLine(com.Name);
                }
                return;
            }
            if (input.IndexOf(' ') >= 0)
            {
                int spaceIndex = input.IndexOf(' ');
                string inputName = (input.Substring(0, spaceIndex)).ToLower();
                string inputArgs = input.Substring(spaceIndex + 1);
                foreach (CommandA com in CommandAList)
                {
                    if (com.Name == inputName)
                    {
                        com.CmdFunction(inputArgs);
                        return;
                    }
                }
                foreach (CommandN com in CommandNList)
                {
                    if (com.Name == inputName)
                    {
                        Console.WriteLine(com.Name + " takes no arguments");
                        return;
                    }
                }
            }
            else
            {
                foreach (CommandN com in CommandNList)
                {
                    if (com.Name == input)
                    {
                        com.CmdFunction();
                        return;
                    }
                }
                foreach (CommandA com in CommandAList)
                {
                    if (com.Name == input)
                    {
                        Console.WriteLine(com.Name + " takes arguments");
                        return;
                    }
                }
            }
            if (cmdFound == false)
            {
                Console.WriteLine("Invalid command");
            }
        }
        public class CommandA
        {
            public string Name;
            public CommandFunctionA CmdFunction;
            public CommandA(string Name, CommandFunctionA CmdFunction)
            {
                this.Name = Name;
                this.CmdFunction = CmdFunction;
            }
        }
        public class CommandN
        {
            public string Name;
            public CommandFunctionN CmdFunction;
            public CommandN(string Name, CommandFunctionN CmdFunction)
            {
                this.Name = Name;
                this.CmdFunction = CmdFunction;
            }
        }
    }
}