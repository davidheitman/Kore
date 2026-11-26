package org.xbmc.kore.utils;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.preference.PreferenceManager;

import org.xbmc.kore.Settings;

import java.security.KeyStore;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Encrypts host passwords at rest with a key held in the Android Keystore.
 *
 * Kore has to present the password to Kodi as HTTP Basic auth, so it cannot be
 * hashed; it has to be recoverable. What this does buy is that the database no
 * longer holds anything usable on its own, which covers backups, device to
 * device transfer and anyone reading the file off the device. It does not, and
 * cannot, stop something already running as Kore, because at that point it can
 * simply ask for the plaintext.
 *
 * The key never leaves the Keystore and is bound to this device, so a database
 * restored onto another phone will not decrypt and the passwords have to be
 * entered again. That is the intended outcome rather than a regression.
 *
 * Where the key lives is decided by what the hardware offers rather than by
 * which build of Android is running. A discrete security module is used when
 * the device has one, which is what FEATURE_STRONGBOX_KEYSTORE reports, and
 * the TEE otherwise. Both are plain AOSP, so this behaves the same on a stock
 * device, on GrapheneOS, and on hardware that does not exist yet.
 */
public final class CredentialCipher {
    private static final String TAG = LogUtils.makeLogTag(CredentialCipher.class);

    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String ALIAS = "kore_host_credential_key";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    /**
     * Marks a value this class produced. Anything without it is a password
     * stored before this existed and is handed back untouched, which is what
     * makes the upgrade silent: there is no migration pass and no schema
     * change, each password is simply encrypted the next time it is saved.
     */
    private static final String PREFIX = "enc:v1:";

    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;
    private static final int B64 = Base64.NO_WRAP;

    private CredentialCipher() {}

    /** How the key is held, for the settings screen to report. */
    public static final int BACKING_NONE = 0;
    public static final int BACKING_SOFTWARE = 1;
    public static final int BACKING_TEE = 2;
    public static final int BACKING_STRONGBOX = 3;

    public static String encrypt(Context context, String plaintext) {
        if (plaintext == null || plaintext.isEmpty() || isEncrypted(plaintext)) {
            return plaintext;
        }
        if (mode(context) == Settings.CREDENTIAL_STORAGE_PLAINTEXT) {
            return plaintext;
        }

        try {
            SecretKey key = getOrCreateKey(context);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            byte[] iv = new byte[IV_BYTES];
            new SecureRandom().nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes("UTF-8"));

            return PREFIX + Base64.encodeToString(iv, B64) + ":" + Base64.encodeToString(ct, B64);
        } catch (Exception e) {
            // Storing it in clear is worse than encrypting it, and better than
            // refusing to save the host the user just typed in. Say so loudly.
            LogUtils.LOGE(TAG, "could not encrypt a host password, storing it as is: " + e);
            return plaintext;
        }
    }

    public static String decrypt(String stored) {
        if (stored == null || !isEncrypted(stored)) {
            return stored;
        }

        try {
            String[] parts = stored.substring(PREFIX.length()).split(":", 2);
            if (parts.length != 2) {
                LogUtils.LOGE(TAG, "a stored password is marked encrypted but malformed");
                return "";
            }
            byte[] iv = Base64.decode(parts[0], B64);
            byte[] ct = Base64.decode(parts[1], B64);

            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            SecretKey key = (SecretKey) ks.getKey(ALIAS, null);
            if (key == null) {
                LogUtils.LOGE(TAG, "the credential key is gone; the password must be entered again");
                return "";
            }

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new String(cipher.doFinal(ct), "UTF-8");
        } catch (Exception e) {
            // A database carried over from another device, or a key the system
            // dropped. An empty password prompts for one rather than sending
            // ciphertext to Kodi as if it were the password.
            LogUtils.LOGE(TAG, "could not decrypt a host password: " + e);
            return "";
        }
    }

    public static boolean isEncrypted(String value) {
        return value != null && value.startsWith(PREFIX);
    }

    private static int mode(Context context) {
        try {
            return Integer.parseInt(PreferenceManager
                    .getDefaultSharedPreferences(context)
                    .getString(Settings.KEY_PREF_CREDENTIAL_STORAGE,
                               String.valueOf(Settings.DEFAULT_PREF_CREDENTIAL_STORAGE)));
        } catch (Exception e) {
            return Settings.DEFAULT_PREF_CREDENTIAL_STORAGE;
        }
    }

    private static synchronized SecretKey getOrCreateKey(Context context) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        SecretKey existing = (SecretKey) ks.getKey(ALIAS, null);
        if (existing != null) {
            return existing;
        }

        boolean wantStrongBox = mode(context) == Settings.CREDENTIAL_STORAGE_AUTO
                && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                && context.getPackageManager()
                          .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);

        if (wantStrongBox) {
            try {
                return generate(true);
            } catch (Exception e) {
                // The feature flag is not a promise: StrongBox can refuse this
                // algorithm or key size, and some devices advertise it and then
                // fail. Falling back to the TEE is the documented response.
                //
                // Caught as Exception rather than StrongBoxUnavailableException
                // on purpose. That class arrived in API 28 and naming it in a
                // catch clause can make older runtimes resolve it while
                // verifying this method, on the very versions that never reach
                // this branch.
                LogUtils.LOGD(TAG, "StrongBox would not hold the key (" + e
                                   + "); using the TEE instead");
            }
        }
        return generate(false);
    }

    private static SecretKey generate(boolean strongBox) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256);

        // Deliberately not setUserAuthenticationRequired: Kore reconnects in the
        // background and from a notification, so a key that needed an unlock
        // first would break playback control rather than protect anything.
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true);
        }

        generator.init(builder.build());
        return generator.generateKey();
    }

    /**
     * Where the key actually ended up, which is not necessarily what was asked
     * for. Checked rather than assumed, because requesting StrongBox and
     * getting it are different things.
     */
    public static int backing(Context context) {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            SecretKey key = (SecretKey) ks.getKey(ALIAS, null);
            if (key == null) {
                return BACKING_NONE;
            }

            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(key.getAlgorithm(), KEYSTORE);
            KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                switch (info.getSecurityLevel()) {
                    case KeyProperties.SECURITY_LEVEL_STRONGBOX:
                        return BACKING_STRONGBOX;
                    case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                        return BACKING_TEE;
                    default:
                        return BACKING_SOFTWARE;
                }
            }
            return info.isInsideSecureHardware() ? BACKING_TEE : BACKING_SOFTWARE;
        } catch (Exception e) {
            LogUtils.LOGD(TAG, "could not read back where the credential key lives: " + e);
            return BACKING_NONE;
        }
    }
}
