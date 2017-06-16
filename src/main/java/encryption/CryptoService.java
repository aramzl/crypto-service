package encryption;

import com.google.common.io.BaseEncoding;
import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

public class CryptoService {
    private static final Logger logger =
            LoggerFactory.getLogger(CryptoService.class);

    private final AlgorithmParameterSpec iv;
    private AlgorithmParameterSpec ivTimeBased;
    private final Key key;

    public CryptoService(byte[] secret, byte[] ivParam, byte[] ivParamTimeBased) {
        if (ivParam.length != 16) {
            throw new RuntimeException("ivParam length should be 16 bytes");
        }
        this.key = makeKey(secret);
        this.iv = makeIv(ivParam);
        this.ivTimeBased = makeIv(ivParamTimeBased);
    }

    public ByteBuffer encrypt(ByteBuffer buffer) {
        return ByteBuffer.wrap(encrypt(buffer.array()));
    }

    public ByteBuffer decrypt(ByteBuffer buffer) {
        return ByteBuffer.wrap(decrypt(buffer.array()));
    }

    public ByteBuffer encryptTimeBased(ByteBuffer buffer) {
        return ByteBuffer.wrap(encryptTimeBased(buffer.array()));
    }

    public ByteBuffer decryptTimeBased(ByteBuffer buffer) {
        return ByteBuffer.wrap(decryptTimeBased(buffer.array()));
    }

    public ByteBuffer decryptTimeBased(ByteBuffer buffer, Key customKey) {
        return ByteBuffer.wrap(decryptTimeBased(buffer.array(), customKey));
    }

    public byte[] encrypt(byte[] msg) {
        return encrypt(msg, key, iv);
    }

    private byte[] encrypt(byte[] msg, Key key, AlgorithmParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            return cipher.doFinal(msg);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decrypt(byte[] encryptedMsg) {
        return decrypt(encryptedMsg, key, iv);
    }

    public byte[] decryptTimeBased(byte[] encryptedMsg, Key previousTimeBasedKey) {
        Key keyTimeBased = generateTimeBasedKey();
        try {
            return decrypt(encryptedMsg, keyTimeBased, ivTimeBased);
        } catch (RuntimeException ex) {
            if (previousTimeBasedKey != null) {
                return decrypt(encryptedMsg, previousTimeBasedKey, ivTimeBased);
            }
            throw ex;
        }
    }

    public byte[] decryptTimeBased(byte[] encryptedMsg) {
        return decryptTimeBased(encryptedMsg, null);
    }

    private byte[] decrypt(byte[] encryptedMsg, Key key, AlgorithmParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return cipher.doFinal(encryptedMsg);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encryptTimeBased(byte[] msg) {
        Key keyTimeBased = generateTimeBasedKey();
        return encrypt(msg, keyTimeBased, ivTimeBased);
    }

    private AlgorithmParameterSpec makeIv(byte[] ivParam) {
        return new IvParameterSpec(ivParam);
    }

    private Key makeKey(byte[] secret) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] key = md.digest(secret);
            logger.info("Key size: " + key.length);
            return new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            logger.error("Cannot create key " + e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    public String currentTimeBasedCode() {
        try {
            BaseEncoding baseEncoding = BaseEncoding.base32();
            return TimeBasedOneTimePasswordUtil.generateCurrentNumberString(baseEncoding.encode(key.getEncoded()));
        } catch (GeneralSecurityException e) {
            logger.error("Cannot generate time based code", e);
            throw new RuntimeException(e);
        }
    }

    public Key generateTimeBasedKey() {
        try {
            return makeKey(xor(key.getEncoded(), currentTimeBasedCode().getBytes("UTF-8")));
        } catch (UnsupportedEncodingException e) {
            logger.error("Cannot generate time based key", e);
            throw new RuntimeException(e);
        }
    }

    byte[] xor(byte[] one, byte[] two) {
        if (one.length >= two.length) {
            for (int i = 0; i < two.length; i++) {
                one[i] ^= two[i];
            }
            return one;
        } else {
            for (int i = 0; i < one.length; i++) {
                two[i] ^= one[i];
            }
            return two;
        }
    }

}
