using Microsoft.AspNetCore.SignalR.Client;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
//using Newtonsoft.Json;
using System.Text.Json;

namespace RSAEncryption
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private HubConnection connection;
        public static KeysContainer keyStorage;
        public RSAParameters privateKey;
        public MainWindow()
        {
            InitializeComponent();
            connection = new HubConnectionBuilder().WithUrl("https://localhost:7070/myhub").Build();
        }
        private bool connected = false;


        /// <summary>
        /// button click to establish connection to server
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void Connect(object sender, RoutedEventArgs e)
        {
            //disconnect if clicked again
            if (connected)
            {
                try
                {
                    await connection.StopAsync();
                    connected = false;
                    connect_label.Content = "disconnected";
                    connectButton.Content = "connect";
                    return;
                }
                catch (Exception)
                {

                    throw;
                }
            }

            //listens when establising a connection and returns a public key to server
            connection.On<string>("connected", (data) =>
            {
                Dispatcher.BeginInvoke(new Action(() => connect_label.Content = $"´session id ( {data} )"));
                Dispatcher.BeginInvoke(new Action(() => connectButton.Content = "connected"));
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    privateKey = rsa.ExportParameters(true);
                    var publicKey = rsa.ExportParameters(false);


                    //convert public key to string
                    string pubKey_string = ConvertPubKeyToString(publicKey);

                    //send key to server
                    connection.InvokeAsync("ReturnSecureKeys", pubKey_string);
                }


            });

            //listens for the method and recieves the evrypted keys
            connection.On<byte[]>("RecieveKeys", (data) =>
            {
                byte[] decryptedData = Decrypt(data, privateKey);
                KeysContainer container = ConvertFromBytes(decryptedData);
                keyStorage = container;
                connected = true;



            });

            //try to establish connection
            try
            {
                await connection.StartAsync();
                // connectButton.Content = $"connected ({_id})";
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);

            }

        }



        /// <summary>
        /// encrypts a string message using symmetric encryption and send it to server
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void SendMessage(object sender, RoutedEventArgs e)
        {
            string message = infoBox.Text;

            using (SymmetricAlgorithm al = Aes.Create())
            {
                al.KeySize = 256;
                al.Key = Convert.FromBase64String(keyStorage.Key);
                al.IV = Convert.FromBase64String(keyStorage.Iv);
                byte[] encryptedData;
                ICryptoTransform encryptor = al.CreateEncryptor();

                using (MemoryStream stream = new MemoryStream())
                {
                    using (CryptoStream crypto = new CryptoStream(stream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(crypto))
                        {
                            writer.Write(message);
                        }

                        encryptedData = stream.ToArray();
                    }

                    connection.InvokeAsync("RecieveMessage", encryptedData);

                }
            }

            connection.On<byte[]>("ReturnMessage", (data) =>
            {
                // Debug.WriteLine(data.Length);

                string decryptedData = Decrypt_Symmetric(data, keyStorage);
                Dispatcher.BeginInvoke(new Action(() => returnBox.Text = decryptedData));
                Debug.WriteLine(decryptedData);
                //  returnBox.Text = decryptedData;



            });

        }


        /// <summary>
        /// decrypts using symmetric encryption and returns a string
        /// </summary>
        /// <param name="data"></param>
        /// <param name="keys"></param>
        /// <returns></returns>
        private static string Decrypt_Symmetric(byte[] data, KeysContainer keys)
        {
            using (SymmetricAlgorithm al = Aes.Create())
            {
                al.KeySize = 256;
                al.Key = Convert.FromBase64String(keys.Key);
                al.IV = Convert.FromBase64String(keys.Iv);

                ICryptoTransform decryptor = al.CreateDecryptor();

                using (MemoryStream stream = new MemoryStream(data))
                {
                    using (CryptoStream crypto = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(crypto))
                        {
                            return reader.ReadToEnd();

                        }
                    }
                }
            }
        }

        /// <summary>
        /// Converts public key to string
        /// </summary>
        /// <param name="pubKey"></param>
        /// <returns></returns>
        private string ConvertPubKeyToString(RSAParameters pubKey)
        {
            var stringWriter = new StringWriter();
            var xml = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xml.Serialize(stringWriter, pubKey);
            return stringWriter.ToString();
        }

        /// <summary>
        /// Decrypts asymmetric data encryption
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        private static byte[] Decrypt(byte[] data, RSAParameters privateKey)
        {
            try
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(privateKey);
                    var decryptedData = rsa.Decrypt(data, false);
                    Debug.WriteLine(decryptedData.Length);
                    return decryptedData;
                }
            }
            catch (CryptographicException cry)
            {

                Debug.WriteLine(cry.Message);
                return null;
            }
        }


        /// <summary>
        /// converts decrypted data to data model
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private static KeysContainer ConvertFromBytes(byte[] data)
        {
            var json = Encoding.UTF8.GetString(data);
            var options = new JsonSerializerOptions { IncludeFields = true };


            KeysContainer deserializedcontainer = JsonSerializer.Deserialize<KeysContainer>(json, options);

            return deserializedcontainer;
        }


    }
}
