using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

class Program
{
    const int Port = 5000;

    // UTF-8 ohne BOM, damit keine unsichtbaren Zeichen am Anfang gesendet werden.
    static readonly Encoding Utf8 = new UTF8Encoding(false);

    // Alle verbundenen Clients (jeweils ein Writer pro Client).
    static readonly List<StreamWriter> clients = new List<StreamWriter>();
    static readonly object lockObject = new object();
    static string serverUsername = "Server";

    static void Main()
    {
        Console.Write("Server oder Client starten? (s/c): ");
        string choice = (Console.ReadLine() ?? "").Trim().ToLower();

        if (choice == "s")
        {
            serverUsername = Ask("Server-Benutzername", "Server");
            string password = Ask("Passwort der server.p12", "");
            StartServer(password);
        }
        else if (choice == "c")
        {
            StartClient();
        }
        else
        {
            Console.WriteLine("Ungueltige Eingabe. Bitte 's' oder 'c' eingeben.");
        }
    }

    // Liest eine Eingabe. Bei leerer Eingabe (nur Enter) wird der Standardwert verwendet.
    static string Ask(string prompt, string defaultValue)
    {
        Console.Write(defaultValue == "" ? $"{prompt}: " : $"{prompt} [{defaultValue}]: ");
        string input = (Console.ReadLine() ?? "").Trim();
        return input == "" ? defaultValue : input;
    }

    // ---------------------------------------------------------------- SERVER

    static void StartServer(string password)
    {
        // Zertifikat neben der .dll suchen, egal aus welchem Ordner gestartet wird.
        string certPath = Path.Combine(AppContext.BaseDirectory, "server.p12");
        if (!File.Exists(certPath))
            certPath = "server.p12"; // Fallback: aktueller Ordner

        X509Certificate2 certificate;
        try
        {
            // Kein EphemeralKeySet: unter Windows kann SslStream damit nicht als Server arbeiten.
            certificate = X509CertificateLoader.LoadPkcs12FromFile(certPath, password);
        }
        catch (CryptographicException)
        {
            Console.WriteLine("[Fehler] Zertifikat konnte nicht geladen werden - falsches Passwort?");
            return;
        }
        catch (FileNotFoundException)
        {
            Console.WriteLine($"[Fehler] server.p12 nicht gefunden ({certPath}).");
            return;
        }

        TcpListener server = new TcpListener(IPAddress.Any, Port);
        server.Start();
        Console.WriteLine($"[{serverUsername}] TLS-Server gestartet auf Port {Port}.");

        Thread sendThread = new Thread(ServerSendMessages) { IsBackground = true };
        sendThread.Start();

        while (true)
        {
            TcpClient client = server.AcceptTcpClient();
            Thread clientThread = new Thread(() => HandleClient(client, certificate)) { IsBackground = true };
            clientThread.Start();
        }
    }

    static void HandleClient(TcpClient client, X509Certificate2 certificate)
    {
        SslStream sslStream = new SslStream(client.GetStream(), false);
        StreamWriter? writer = null;

        try
        {
            sslStream.AuthenticateAsServer(certificate, false, SslProtocols.Tls12 | SslProtocols.Tls13, false);

            // Reader/Writer arbeiten zeilenweise: eine Zeile = eine Nachricht.
            StreamReader reader = new StreamReader(sslStream, Utf8);
            writer = new StreamWriter(sslStream, Utf8) { AutoFlush = true };

            lock (lockObject)
            {
                clients.Add(writer);
            }

            Console.WriteLine("[Server] Verschluesselter Client verbunden.");

            string? msg;
            while ((msg = reader.ReadLine()) != null) // null = Client hat getrennt
            {
                Console.WriteLine(msg);
                BroadcastMessage(msg, writer);
            }

            Console.WriteLine("[Server] Client hat die Verbindung beendet.");
        }
        catch (Exception e)
        {
            Console.WriteLine("[Server] Verbindung beendet: " + e.Message);
        }
        finally
        {
            if (writer != null)
            {
                lock (lockObject)
                {
                    clients.Remove(writer);
                }
            }

            sslStream.Dispose();
            client.Close();
        }
    }

    static void ServerSendMessages()
    {
        while (true)
        {
            string? message = Console.ReadLine();
            if (message == null) return; // Eingabe geschlossen

            if (!string.IsNullOrWhiteSpace(message))
            {
                BroadcastMessage($"[{serverUsername}]: {message}", null);
            }
        }
    }

    // Schickt eine Nachricht an alle Clients ausser dem Absender.
    static void BroadcastMessage(string message, StreamWriter? sender)
    {
        lock (lockObject)
        {
            foreach (StreamWriter client in clients)
            {
                if (client == sender) continue;

                try
                {
                    client.WriteLine(message);
                }
                catch
                {
                    // Defekte Verbindung wird vom eigenen Thread beim Lesen entfernt.
                }
            }
        }
    }

    // ---------------------------------------------------------------- CLIENT

    static void StartClient()
    {
        try
        {
            string serverIp = Ask("IP-Adresse des Servers", "localhost");
            string username = Ask("Benutzername", "Client");

            TcpClient client = new TcpClient(serverIp, Port);

            // Nur fuer diesen Test: Zertifikatspruefung wird uebersprungen.
            // In einer echten Anwendung muss das Serverzertifikat geprueft werden.
            SslStream sslStream = new SslStream(client.GetStream(), false, (s, cert, chain, errors) => true);
            sslStream.AuthenticateAsClient("localhost", null, SslProtocols.Tls12 | SslProtocols.Tls13, false);

            StreamReader reader = new StreamReader(sslStream, Utf8);
            StreamWriter writer = new StreamWriter(sslStream, Utf8) { AutoFlush = true };

            Console.WriteLine("[Client] TLS-Verbindung hergestellt. Mit /quit beenden.");

            // Empfangen laeuft im Hintergrund.
            Thread receiveThread = new Thread(() =>
            {
                try
                {
                    string? msg;
                    while ((msg = reader.ReadLine()) != null)
                    {
                        Console.WriteLine(msg);
                    }
                    Console.WriteLine("[Client] Server hat die Verbindung beendet.");
                }
                catch
                {
                    Console.WriteLine("[Client] Verbindung getrennt.");
                }

                // Programm beenden, auch wenn der Haupt-Thread noch auf Eingabe wartet.
                Environment.Exit(0);
            }) { IsBackground = true };
            receiveThread.Start();

            // Senden laeuft im Haupt-Thread.
            while (true)
            {
                string? message = Console.ReadLine();
                if (message == null || message.Trim() == "/quit") break;
                if (string.IsNullOrWhiteSpace(message)) continue;

                writer.WriteLine($"[{username}]: {message}");
            }

            sslStream.Dispose();
            client.Close();
        }
        catch (Exception e)
        {
            Console.WriteLine("[Client Fehler]: " + e.Message);
        }
    }
}
