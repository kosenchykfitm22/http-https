
using SharpPcap;
using SharpPcap.LibPcap;

using PacketDotNet;
using System.Text;

const int HTTP_PORT = 8081;

var devices = CaptureDeviceList.Instance;
if (devices.Count < 1)
{
    Console.WriteLine("Не знайдено жодного мережевого адаптера. Переконайтеся, що Npcap/WinPcap встановлено.");
    return;
}

Console.WriteLine("Доступні мережеві адаптери:");
for (int i = 0; i < devices.Count; i++)
{
    Console.WriteLine($"{i}): {devices[i].Description}");
}

Console.WriteLine("\nВведіть номер адаптера для прослуховування (шукайте 'Loopback' для localhost):");
int deviceIndex;
while (!int.TryParse(Console.ReadLine(), out deviceIndex) || deviceIndex < 0 || deviceIndex >= devices.Count)
{
    Console.WriteLine("Невірний вибір. Спробуйте ще раз:");
}

var device = devices[deviceIndex];
Console.WriteLine($"\nВибрано адаптер: {device.Description}");
Console.WriteLine($"Слухаємо трафік на TCP-порті {HTTP_PORT}...");
Console.WriteLine("Натисніть Ctrl+C для зупинки.\n");

device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

device.Open(DeviceModes.Promiscuous, 1000);

string filter = $"tcp port {HTTP_PORT}";
device.Filter = filter;

device.StartCapture();

Console.ReadLine();

device.StopCapture();
device.Close();


static void device_OnPacketArrival(object sender, PacketCapture e)
{
    var rawPacket = e.GetPacket();
    var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
    
    var ipPacket = packet.Extract<IPPacket>();
    var tcpPacket = packet.Extract<TcpPacket>();

    if (ipPacket == null || tcpPacket == null)
        return;

    if (tcpPacket.DestinationPort != HTTP_PORT)
        return;
        

    byte[] payload = tcpPacket.PayloadData;
    
    if (payload.Length > 0)
    {
        string payloadStr = Encoding.ASCII.GetString(payload).Trim();
        
        if (payloadStr.StartsWith("POST") && 
            (payloadStr.Contains("username=") || payloadStr.Contains("password=")) &&
            !payloadStr.Contains("TLS")) 
        
            Console.WriteLine("\n" + new string('=', 50));
            Console.WriteLine("💥 ЗНАЙДЕНО ВРАЗЛИВІ ДАНІ (HTTP POST):");
            Console.WriteLine($"  Source: {ipPacket.SourceAddress}:{tcpPacket.SourcePort}");
            Console.WriteLine($"  Destination: {ipPacket.DestinationAddress}:{tcpPacket.DestinationPort}");
            Console.WriteLine("\n  ТІЛО ЗАПИТУ (ОТКРИТИЙ ТЕКСТ):");
            
            Console.WriteLine(payloadStr.Substring(0, Math.Min(payloadStr.Length, 500)));
            Console.WriteLine(new string('=', 50) + "\n");
        }
        
    }
}
