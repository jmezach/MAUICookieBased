// While updating my codebase to use .NET MAUI instead of Xamarin Forms, I had trouble accessing values I securely stored using 
// Xamarin Essentials' SecureStorage class. The old keys I was using werent working for the new MAUI SecureStorage class. Here is a helper 
// class that you can use to extract those old saved values.  It uses the same Xamarin Essentials SecureStorage class code MINUS the Set functionality which leaves:

// Task<string> GetAsync(string key)
// bool RemoveKey(string key)
// void RemoveAll()

// IMPORTANT - Make sure you have an Entitlements.plist with the following:
//    <key>keychain-access-groups</key>
//    <string>$(AppIdentifierPrefix)$(CFBundleIdentifier)</string>
// and that the Entitlements.plist is set in the Custom Entitlements field for Bundle Signing

// Coder beware.  I tested this except for Android Version < 23.  Test for yourself before using it.  Not my fault if it breaks something.

using System;
using System.Text;
using System.Globalization;
using System.Threading.Tasks;

#if ANDROID

using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Security;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;

#elif IOS

using Foundation;
using Security;

#endif

namespace MAUICookieBasedTest.Services;

public static class LegacySecureStorage
{
    internal static readonly string alias = $"{AppInfo.PackageName}.xamarinessentials";

    public static Task<string> GetAsync(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
            throw new ArgumentNullException(nameof(key));

        var result = String.Empty;

#if ANDROID
        var locker = new object();
        var encVal = Preferences.Get(key, null, alias);

        if (!String.IsNullOrEmpty(encVal))
        {
            var encData = Convert.FromBase64String(encVal);
            lock (locker)
            {
                var ks = new AndroidKeyStore(Platform.AppContext, alias, false);
                result = ks.Decrypt(encData);
            }
        }
#elif IOS
        var kc = new KeyChain();
        result = kc.ValueForKey(key, alias);
#endif

        return Task.FromResult(result);
    }

    public static bool Remove(string key)
    {
        var result = false;

#if ANDROID
        Preferences.Clear(alias);
        result = true;
#elif IOS
        var kc = new KeyChain();
        result = kc.Remove(key, alias);
#endif

        return result;
    }

    public static void RemoveAll()
    {
#if ANDROID
        Preferences.Clear(alias);
#elif IOS
        var kc = new KeyChain();
        kc.RemoveAll(alias);
#endif
    }
}

#if ANDROID
// https://github.com/xamarin/Essentials/blob/7218ab88f7fbe00ec3379bd54e6c0ce35ffc0c22/Xamarin.Essentials/SecureStorage/SecureStorage.android.cs

class AndroidKeyStore
{
    const string androidKeyStore = "AndroidKeyStore"; // this is an Android const value
    const string aesAlgorithm = "AES";
    const string cipherTransformationAsymmetric = "RSA/ECB/PKCS1Padding";
    const string cipherTransformationSymmetric = "AES/GCM/NoPadding";
    const string prefsMasterKey = "SecureStorageKey";
    const int initializationVectorLen = 12; // Android supports an IV of 12 for AES/GCM

    internal AndroidKeyStore(Context context, string keystoreAlias, bool alwaysUseAsymmetricKeyStorage)
    {
        alwaysUseAsymmetricKey = alwaysUseAsymmetricKeyStorage;
        appContext = context;
        alias = keystoreAlias;

        keyStore = KeyStore.GetInstance(androidKeyStore);
        keyStore.Load(null);
    }

    readonly Context appContext;
    readonly string alias;
    readonly bool alwaysUseAsymmetricKey;
    readonly string useSymmetricPreferenceKey = "essentials_use_symmetric";

    KeyStore keyStore;
    bool useSymmetric = false;

    ISecretKey GetKey()
    {
        // check to see if we need to get our key from past-versions or newer versions.
        // we want to use symmetric if we are >= 23 or we didn't set it previously.
        var hasApiLevel = Build.VERSION.SdkInt >= BuildVersionCodes.M;

        useSymmetric = Preferences.Get(useSymmetricPreferenceKey, hasApiLevel, alias);

        // If >= API 23 we can use the KeyStore's symmetric key
        if (useSymmetric && !alwaysUseAsymmetricKey)
            return GetSymmetricKey();

        // NOTE: KeyStore in < API 23 can only store asymmetric keys
        // specifically, only RSA/ECB/PKCS1Padding
        // So we will wrap our symmetric AES key we just generated
        // with this and save the encrypted/wrapped key out to
        // preferences for future use.
        // ECB should be fine in this case as the AES key should be
        // contained in one block.

        // Get the asymmetric key pair
        var keyPair = GetAsymmetricKeyPair();

        var existingKeyStr = Preferences.Get(prefsMasterKey, null, alias);

        if (!string.IsNullOrEmpty(existingKeyStr))
        {
            try
            {
                var wrappedKey = Convert.FromBase64String(existingKeyStr);

                var unwrappedKey = UnwrapKey(wrappedKey, keyPair.Private);
                var kp = unwrappedKey.JavaCast<ISecretKey>();

                return kp;
            }
            catch (InvalidKeyException ikEx)
            {
                System.Diagnostics.Debug.WriteLine($"Unable to unwrap key: Invalid Key. This may be caused by system backup or upgrades. All secure storage items will now be removed. {ikEx.Message}");
            }
            catch (IllegalBlockSizeException ibsEx)
            {
                System.Diagnostics.Debug.WriteLine($"Unable to unwrap key: Illegal Block Size. This may be caused by system backup or upgrades. All secure storage items will now be removed. {ibsEx.Message}");
            }
            catch (BadPaddingException paddingEx)
            {
                System.Diagnostics.Debug.WriteLine($"Unable to unwrap key: Bad Padding. This may be caused by system backup or upgrades. All secure storage items will now be removed. {paddingEx.Message}");
            }
            SecureStorage.RemoveAll();
        }

        var keyGenerator = KeyGenerator.GetInstance(aesAlgorithm);
        var defSymmetricKey = keyGenerator.GenerateKey();

        var newWrappedKey = WrapKey(defSymmetricKey, keyPair.Public);

        Preferences.Set(prefsMasterKey, Convert.ToBase64String(newWrappedKey), alias);

        return defSymmetricKey;
    }

    // API 23+ Only
#pragma warning disable CA1416
    ISecretKey GetSymmetricKey()
    {
        Preferences.Set(useSymmetricPreferenceKey, true, alias);

        var existingKey = keyStore.GetKey(alias, null);

        if (existingKey != null)
        {
            var existingSecretKey = existingKey.JavaCast<ISecretKey>();
            return existingSecretKey;
        }

        var keyGenerator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, androidKeyStore);
        var builder = new KeyGenParameterSpec.Builder(alias, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
            .SetBlockModes(KeyProperties.BlockModeGcm)
            .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone)
            .SetRandomizedEncryptionRequired(false);

        keyGenerator.Init(builder.Build());

        return keyGenerator.GenerateKey();
    }
#pragma warning restore CA1416

    KeyPair GetAsymmetricKeyPair()
    {
        // set that we generated keys on pre-m device.
        Preferences.Set(useSymmetricPreferenceKey, false, alias);

        var asymmetricAlias = $"{alias}.asymmetric";

        var privateKey = keyStore.GetKey(asymmetricAlias, null)?.JavaCast<IPrivateKey>();
        var publicKey = keyStore.GetCertificate(asymmetricAlias)?.PublicKey;

        // Return the existing key if found
        if (privateKey != null && publicKey != null)
            return new KeyPair(publicKey, privateKey);

        var originalLocale = Java.Util.Locale.Default;
        try
        {
            // Force to english for known bug in date parsing:
            // https://issuetracker.google.com/issues/37095309
            SetLocale(Java.Util.Locale.English);

            // Otherwise we create a new key
#pragma warning disable CA1416
            var generator = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmRsa, androidKeyStore);
#pragma warning restore CA1416

            var end = DateTime.UtcNow.AddYears(20);
            var startDate = new Java.Util.Date();
#pragma warning disable CS0618 // Type or member is obsolete
            var endDate = new Java.Util.Date(end.Year, end.Month, end.Day);
#pragma warning restore CS0618 // Type or member is obsolete

#pragma warning disable CS0618
            var builder = new KeyPairGeneratorSpec.Builder(Platform.AppContext)
                .SetAlias(asymmetricAlias)
                .SetSerialNumber(Java.Math.BigInteger.One)
                .SetSubject(new Javax.Security.Auth.X500.X500Principal($"CN={asymmetricAlias} CA Certificate"))
                .SetStartDate(startDate)
                .SetEndDate(endDate);

            generator.Initialize(builder.Build());
#pragma warning restore CS0618

            return generator.GenerateKeyPair();
        }
        finally
        {
            SetLocale(originalLocale);
        }
    }

    byte[] WrapKey(IKey keyToWrap, IKey withKey)
    {
        var cipher = Cipher.GetInstance(cipherTransformationAsymmetric);
        cipher.Init(CipherMode.WrapMode, withKey);
        return cipher.Wrap(keyToWrap);
    }

#pragma warning disable CA1416
    IKey UnwrapKey(byte[] wrappedData, IKey withKey)
    {
        var cipher = Cipher.GetInstance(cipherTransformationAsymmetric);
        cipher.Init(CipherMode.UnwrapMode, withKey);
        var unwrapped = cipher.Unwrap(wrappedData, KeyProperties.KeyAlgorithmAes, KeyType.SecretKey);
        return unwrapped;
    }
#pragma warning restore CA1416

    internal string Decrypt(byte[] data)
    {
        if (data.Length < initializationVectorLen)
            return null;

        var key = GetKey();

        // IV will be the first 16 bytes of the encrypted data
        var iv = new byte[initializationVectorLen];
        Buffer.BlockCopy(data, 0, iv, 0, initializationVectorLen);

        Cipher cipher;

        // Attempt to use GCMParameterSpec by default
        try
        {
            cipher = Cipher.GetInstance(cipherTransformationSymmetric);
            cipher.Init(CipherMode.DecryptMode, key, new GCMParameterSpec(128, iv));
        }
        catch (InvalidAlgorithmParameterException)
        {
            // If we encounter this error, it's likely an old bouncycastle provider version
            // is being used which does not recognize GCMParameterSpec, but should work
            // with IvParameterSpec, however we only do this as a last effort since other
            // implementations will error if you use IvParameterSpec when GCMParameterSpec
            // is recognized and expected.
            cipher = Cipher.GetInstance(cipherTransformationSymmetric);
            cipher.Init(CipherMode.DecryptMode, key, new IvParameterSpec(iv));
        }

        // Decrypt starting after the first 16 bytes from the IV
        var decryptedData = cipher.DoFinal(data, initializationVectorLen, data.Length - initializationVectorLen);

        return Encoding.UTF8.GetString(decryptedData);
    }

    internal void SetLocale(Java.Util.Locale locale)
    {
        Java.Util.Locale.Default = locale;
        var resources = appContext.Resources;
        var config = resources.Configuration;

        if (Build.VERSION.SdkInt >= BuildVersionCodes.N)
            config.SetLocale(locale);
        else
#pragma warning disable CS0618 // Type or member is obsolete
            config.Locale = locale;
#pragma warning restore CS0618 // Type or member is obsolete

#pragma warning disable CS0618 // Type or member is obsolete
        resources.UpdateConfiguration(config, resources.DisplayMetrics);
#pragma warning restore CS0618 // Type or member is obsolete
    }
}

#elif IOS

// https://github.com/xamarin/Essentials/blob/7218ab88f7fbe00ec3379bd54e6c0ce35ffc0c22/Xamarin.Essentials/SecureStorage/SecureStorage.ios.tvos.watchos.macos.cs
class KeyChain
{
    SecRecord ExistingRecordForKey(string key, string service)
    {
        return new SecRecord(SecKind.GenericPassword)
        {
            Account = key,
            Service = service
        };
    }

    internal string ValueForKey(string key, string service)
    {
        using (var record = ExistingRecordForKey(key, service))
        using (var match = SecKeyChain.QueryAsRecord(record, out var resultCode))
        {
            if (resultCode == SecStatusCode.Success)
                return NSString.FromData(match.ValueData, NSStringEncoding.UTF8);
            else
                return null;
        }
    }

    internal bool Remove(string key, string service)
    {
        using (var record = ExistingRecordForKey(key, service))
        using (var match = SecKeyChain.QueryAsRecord(record, out var resultCode))
        {
            if (resultCode == SecStatusCode.Success)
            {
                RemoveRecord(record);
                return true;
            }
        }
        return false;
    }

    internal void RemoveAll(string service)
    {
        using (var query = new SecRecord(SecKind.GenericPassword) { Service = service })
        {
            SecKeyChain.Remove(query);
        }
    }

    bool RemoveRecord(SecRecord record)
    {
        var result = SecKeyChain.Remove(record);
        if (result != SecStatusCode.Success && result != SecStatusCode.ItemNotFound)
            throw new Exception($"Error removing record: {result}");

        return true;
    }
}

#endif