using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace NGC_Demo
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {

        const string _userName = "4NGC_Bo Wang";

        string _key = "";

        public MainPage()
        {
            this.InitializeComponent();

            this.Loaded += MainPage_Loaded;
        }

        private void MainPage_Loaded(object sender, RoutedEventArgs e)
        {
            //bool result = await CreatePassportKey(_userName);

            //bool result = await AuthenticatePassport();

            //Windows.System.Diagnostics.ProcessMemoryUsageReport

            username.Text = "绑定用户名称: " + _userName;
        }


        private async Task<bool> CreatePassportKey(string accountId)
        {
            KeyCredentialRetrievalResult keyCreationResult = await KeyCredentialManager.RequestCreateAsync(accountId, KeyCredentialCreationOption.ReplaceExisting);

            if (keyCreationResult.Status == KeyCredentialStatus.Success)
            {
                KeyCredential userKey = keyCreationResult.Credential;
                IBuffer publicKey = userKey.RetrievePublicKey();
                KeyCredentialAttestationResult keyAttestationResult = await userKey.GetAttestationAsync();

                // Convert the hash to a string (for display).
                String strpublicKey = CryptographicBuffer.EncodeToBase64String(publicKey);
                _key = strpublicKey;

                //Add this credential pair to PasswordVault
                PasswordCredential credentials = new PasswordCredential();
                credentials.UserName = strpublicKey;
                credentials.Password = strpublicKey;
                credentials.Resource = _userName;
                PasswordVault vault = new PasswordVault();
                vault.Add(credentials);


                IBuffer keyAttestation = null;
                IBuffer certificateChain = null;
                bool keyAttestationIncluded = false;
                bool keyAttestationCanBeRetrievedLater = false;
                KeyCredentialAttestationStatus keyAttestationRetryType = 0;

                if (keyAttestationResult.Status == KeyCredentialAttestationStatus.Success)
                {
                    keyAttestationIncluded = true;
                    keyAttestation = keyAttestationResult.AttestationBuffer;
                    certificateChain = keyAttestationResult.CertificateChainBuffer;
                    // rootPage.NotifyUser("Successfully made key and attestation", NotifyType.StatusMessage);
                }
                else if (keyAttestationResult.Status == KeyCredentialAttestationStatus.TemporaryFailure)
                {
                    keyAttestationRetryType = KeyCredentialAttestationStatus.TemporaryFailure;
                    keyAttestationCanBeRetrievedLater = true;
                    // rootPage.NotifyUser("Successfully made key but not attestation", NotifyType.StatusMessage);
                }
                else if (keyAttestationResult.Status == KeyCredentialAttestationStatus.NotSupported)
                {
                    keyAttestationRetryType = KeyCredentialAttestationStatus.NotSupported;
                    keyAttestationCanBeRetrievedLater = false;
                    // rootPage.NotifyUser("Key created, but key attestation not supported", NotifyType.StatusMessage);
                }

                // Package public key, keyAttesation if available, 
                // certificate chain for attestation endorsement key if available,  
                // status code of key attestation result: keyAttestationIncluded or 
                // keyAttestationCanBeRetrievedLater and keyAttestationRetryType
                // and send it to application server to register the user.
                //bool serverAddedPassportToAccount = await AddPassportToAccountOnServer();

                //if (serverAddedPassportToAccount == true)
                //{
                //    return true;
                //}
            }
            else if (keyCreationResult.Status == KeyCredentialStatus.UserCanceled)
            {
                // User cancelled the Passport enrollment process
                //take the password authentication and take him to Stockwatcher list page
            }
            else if (keyCreationResult.Status == KeyCredentialStatus.NotFound)
            {
                // User needs to create PIN
                //textblock_PassportStatusText.Text = "Microsoft Passport is almost ready!\nPlease go to Windows Settings and set up a PIN to use it.";
                //grid_PassportStatus.Background = new SolidColorBrush(Color.FromArgb(255, 50, 170, 207));
                //button_PassportSignIn.IsEnabled = false;

                //m_passportAvailable = false;
            }
            else
            {
                // rootPage.NotifyUser(keyCreationResult.Status.ToString(), NotifyType.ErrorMessage);
            }

            return false;
        }

        private async Task<bool> AuthenticatePassport()
        {
            IBuffer message = CryptographicBuffer.ConvertStringToBinary("LoginAuth", BinaryStringEncoding.Utf8);
            IBuffer authMessage = await GetPassportAuthenticationMessage(message, _userName);

            if (authMessage != null)
            {
                return true;
            }
            return false;
        }

        private async Task<IBuffer> GetPassportAuthenticationMessage(IBuffer message, string accountId)
        {
            KeyCredentialRetrievalResult openKeyResult = await KeyCredentialManager.OpenAsync(accountId);

            if (openKeyResult.Status == KeyCredentialStatus.Success)
            {
                KeyCredential userKey = openKeyResult.Credential;
                IBuffer publicKey = userKey.RetrievePublicKey();

                // Convert the hash to a string (for display).
                String strpublicKey = CryptographicBuffer.EncodeToBase64String(publicKey);

                _key = strpublicKey;

                KeyCredentialOperationResult signResult = await userKey.RequestSignAsync(message);

                if (signResult.Status == KeyCredentialStatus.Success)
                {
                    return signResult.Result;
                }
                else if (signResult.Status == KeyCredentialStatus.UserCanceled)
                {
                    // User cancelled the Passport PIN entry.
                    //
                    // We will return null below this and the username/password
                    // sign in form will show.
                }
                else if (signResult.Status == KeyCredentialStatus.NotFound)
                {
                    // Must recreate Passport key
                }
                else if (signResult.Status == KeyCredentialStatus.SecurityDeviceLocked)
                {
                    // Can't use Passport right now, remember that hardware failed and suggest restart
                }
                else if (signResult.Status == KeyCredentialStatus.UnknownError)
                {
                    // Can't use Passport right now, try again later
                }
                return null;
            }
            else if (openKeyResult.Status == KeyCredentialStatus.NotFound)
            {
                // Passport key lost, need to recreate it
                //textblock_PassportStatusText.Text = "Microsoft Passport is almost ready!\nPlease go to Windows Settings and set up a PIN to use it.";
                //grid_PassportStatus.Background = new SolidColorBrush(Color.FromArgb(255, 50, 170, 207));
                //button_PassportSignIn.IsEnabled = false;

                //m_passportAvailable = false;
            }
            else
            {
                // Can't use Passport right now, try again later
            }
            return null;
        }

        private async void btn_reg_Click(object sender, RoutedEventArgs e)
        {
            bool result = await CreatePassportKey(_userName);
            MessageDialog msgbox = new MessageDialog(_key, "注册成功");
            await msgbox.ShowAsync();
        }

        private async void btn_login_Click(object sender, RoutedEventArgs e)
        {
            bool result = await AuthenticatePassport();
            MessageDialog msgbox = new MessageDialog(_key, "验证成功");
            await msgbox.ShowAsync();
        }
    }
}
