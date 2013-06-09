/*This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.*/

using System;
using System.Net.Sockets;

namespace BlueWombat.DotSyslog
{
    public enum Levels
    {
        /// <summary>
        /// system is unusable
        /// </summary>
        Emergency = 0,
        /// <summary>
        /// action must be taken immediately
        /// </summary>
        Alert = 1,
        /// <summary>
        /// critical conditions
        /// </summary>
        Critical = 2,
        /// <summary>
        /// error conditions
        /// </summary>
        Error = 3,
        /// <summary>
        /// warning conditions
        /// </summary>
        Warning = 4,
        /// <summary>
        /// normal but significant condition
        /// </summary>
        Notice = 5,
        /// <summary>
        /// informational messages
        /// </summary>
        Information = 6,
        /// <summary>
        /// debug-level messages
        /// </summary>
        Debug = 7
    }

    public enum Facilities
    {
        /// <summary>
        /// kernel messages
        /// </summary>
        Kernel = 0,
        /// <summary>
        /// user-level messages
        /// </summary>
        User = 1,
        /// <summary>
        /// mail system
        /// </summary>
        Mail = 2,
        /// <summary>
        /// system daemons
        /// </summary>
        Daemon = 3,
        /// <summary>
        /// security/authorization messages. Note: Various operating systems have been found to utilize Facilities 4, 10, 13 and 14 for security/authorization, audit, and alert messages which seem to be similar.
        /// </summary>
        Auth = 4,
        /// <summary>
        /// messages generated internally by syslogd
        /// </summary>
        Syslog = 5,
        /// <summary>
        /// line printer subsystem
        /// </summary>
        Lpr = 6,
        /// <summary>
        /// network news subsystem
        /// </summary>
        News = 7,
        /// <summary>
        /// UUCP subsystem
        /// </summary>
        UUCP = 8,
        /// <summary>
        /// clock daemon Note: Various operating systems have been found to utilize both Facilities 9 and 15 for clock (cron/at) messages.
        /// </summary>
        Cron = 9,
        /// <summary>
        /// security/authorization messages Note: Various operating systems have been found to utilize Facilities 4, 10, 13 and 14 for security/authorization, audit, and alert messages which seem to be similar.
        /// </summary>
        Auth2 = 10,
        /// <summary>
        /// FTP daemon
        /// </summary>
        ftpd = 11,
        /// <summary>
        /// NTP subsystem
        /// </summary>
        ntp = 12,
        /// <summary>
        /// log audit Note: Various operating systems have been found to utilize Facilities 4, 10, 13 and 14 for security/authorization, audit, and alert messages which seem to be similar.
        /// </summary>
        logAudit = 13,
        /// <summary>
        /// log alert Note: Various operating systems have been found to utilize Facilities 4, 10, 13 and 14 for security/authorization, audit, and alert messages which seem to be similar.
        /// </summary>
        logAlert = 14,
        /// <summary>
        /// clock daemon Note: Various operating systems have been found to utilize both Facilities 9 and 15 for clock (cron/at) messages.
        /// </summary>
        Cron2 = 15,
        /// <summary>
        /// local use 0  (local0)
        /// </summary>
        Local0 = 16,
        /// <summary>
        /// local use 1  (local1)
        /// </summary>
        Local1 = 17,
        /// <summary>
        /// local use 2  (local2)
        /// </summary>
        Local2 = 18,
        /// <summary>
        /// local use 3  (local3)
        /// </summary>
        Local3 = 19,
        /// <summary>
        /// local use 4  (local4)
        /// </summary>
        Local4 = 20,
        /// <summary>
        /// local use 5  (local5)
        /// </summary>
        Local5 = 21,
        /// <summary>
        /// local use 6  (local6)
        /// </summary>
        Local6 = 22,
        /// <summary>
        /// local use 7  (local7)
        /// </summary>
        Local7 = 23
    }

    public class Message
    {
        /// <summary>
        /// Origin of the message
        /// </summary>
        public Facilities Facility { get; set; }
        /// <summary>
        /// How severe the event described in the message is
        /// </summary>
        public Levels Severity { get; set; }
        /// <summary>
        /// The actual message
        /// </summary>
        public string Text { get; set; }
        /// <summary>
        /// Machine/application designator
        /// </summary>
        public string MachineName { get; set; }
        /// <summary>
        /// Fragmentation keyword
        /// </summary>
        public string Tag { get; set; }
        /// <summary>
        /// ID of the process triggering the log entry
        /// </summary>
        public int? PID { get; set; }
        /// <summary>
        /// Instantiates a new Message object
        /// </summary>
        public Message() { }

        public byte[] GetBytes()
        {
            string messageString = GetString();
            return System.Text.Encoding.ASCII.GetBytes(messageString);
        }

        private string GetString()
        {
            int priority = (int)this.Facility * 8 + (int)this.Severity;
            return string.Format("<{0}>{1} {2} {3}: {4}",
                                              priority,
                                              DateTime.Now.ToString("MMM dd HH:mm:ss"),
                                              this.MachineName,
                                              this.Tag + (this.PID == null ? "" : "[" + this.PID + "]"),
                                              this.Text.Replace("\r\n", " ").Replace('\r', ' ').Replace('\n', ' '));
        }
    }

    public class SyslogSocketException : Exception
    {
        public SyslogSocketException(string message)
            : base(message)
        {
        }
    }

    /// <summary>
    /// A Syslog client implemented according to the RFC-3164 specification (The BSD syslog Protocol), see <see cref="http://tools.ietf.org/html/rfc3164"/> for further reference
    /// </summary>
    public class Client : IDisposable
    {
        /// need this helper class to expose the Active property of UdpClient
        private class UdpClientExposed : UdpClient
        {
            public UdpClientExposed() : base() { }
            public bool IsActive
            {
                get { return this.Active; }
            }
        }

        private UdpClientExposed udpClient;

        private int _Port = 514;
        /// <summary>
        /// Port that Syslog deamon at endpoint listens to, default is 514
        /// </summary>
        public int Port
        {
            set { this._Port = value; }
            get { return this._Port; }
        }

        private string _IP = null;
        /// <summary>
        /// IP of the Syslog endpoint
        /// </summary>
        public string IP
        {
            get { return _IP; }
            set
            {
                if (this._IP == null && !this.IsActive)
                    this._IP = value;
            }
        }

        /// <summary>
        /// A client for connecting and sending messages to a Syslog server
        /// </summary>
        public Client()
        {
            udpClient = new UdpClientExposed();
        }

        private bool IsActive
        {
            get { return udpClient.IsActive; }
        }

        /// <summary>
        /// Closes the connection to the Syslog server
        /// </summary>
        public void Close()
        {
            if (this.IsActive)
                udpClient.Close();
        }

        /// <summary>
        /// Closes the connection to the Syslog server, and disposes itself
        /// </summary>
        public void Dispose()
        {
            this.Close();
            ((IDisposable)udpClient).Dispose();
        }

        /// <summary>
        /// Send the log message
        /// </summary>
        /// <param name="message">The message for logging</param>
        public void Send(Message message)
        {
            if (!udpClient.IsActive)
                udpClient.Connect(_IP, _Port);
            if (udpClient.IsActive)
            {
                byte[] messageBytes = message.GetBytes();
                udpClient.Send(messageBytes, messageBytes.Length);
            }
            else
                throw new SyslogSocketException("Syslog client Socket is not connected");
        }
    }
}
