package encryption;

import com.google.common.io.BaseEncoding;
import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import org.testng.annotations.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

public class CryptoServiceTest {

    private String secret = "12345678901234561234567890123456";
    private String ivParam = "4e5Wa71fYoT7MFEX";
    private String ivParamTimeBased = "4e5Wa71fYoT7MFEX";
    private CryptoService cut = new CryptoService(secret.getBytes(), ivParam.getBytes(), ivParamTimeBased.getBytes());

    @Test
    public void testEncryption() {
        ByteBuffer buffer = ByteBuffer.wrap("foobar".getBytes());
        ByteBuffer encryptedBuffer = cut.encrypt(buffer);
        assertNotEquals(buffer.array(), encryptedBuffer.array());
        System.out.println(new String(buffer.array()));
        System.out.println(buffer.array().length);
        System.out.println(new String(encryptedBuffer.array()));
        System.out.println(encryptedBuffer.array().length);
        ByteBuffer decryptedBuffer = cut.decrypt(encryptedBuffer);
        System.out.println(new String(decryptedBuffer.array()));
        assertEquals(buffer.array(), decryptedBuffer.array());
    }

    @Test
    public void testTimeBasedEncryption() {
        ByteBuffer buffer = ByteBuffer.wrap("foobar".getBytes());
        ByteBuffer encryptedBuffer = cut.encryptTimeBased(buffer);
        assertNotEquals(buffer.array(), encryptedBuffer.array());
        System.out.println(new String(buffer.array()));
        System.out.println(buffer.array().length);
        System.out.println(new String(encryptedBuffer.array()));
        System.out.println(encryptedBuffer.array().length);
        ByteBuffer decryptedBuffer = cut.decryptTimeBased(encryptedBuffer);
        System.out.println(new String(decryptedBuffer.array()));
        assertEquals(buffer.array(), decryptedBuffer.array());
    }

    @Test
    public void testTOTPCodeGeneration() throws GeneralSecurityException {
        String expected = expectedCurrentNumber();
        String keySupplement = cut.currentTimeBasedCode();

        assertEquals(expected, keySupplement);
    }

    @Test
    public void testTimeBasedKeyGeneration() throws GeneralSecurityException, UnsupportedEncodingException {
        String expected = expectedCurrentNumber();
        Key key = cut.generateTimeBasedKey();

        byte[] timeBased = expected.getBytes("UTF-8");
        byte[] sec = createKey(secret.getBytes()).getEncoded();

        byte[] newKey = cut.xor(sec, timeBased);
        Key expectedKey = createKey(newKey);

        assertEquals(expectedKey.getEncoded(), key.getEncoded());
    }

    @Test
    public void testPastKey() throws InterruptedException {
        ByteBuffer buffer = ByteBuffer.wrap("foobar".getBytes());
        ByteBuffer encryptedBuffer = cut.encryptTimeBased(buffer);
        assertNotEquals(buffer.array(), encryptedBuffer.array());

        Key timeBasedKey = cut.generateTimeBasedKey();
        Thread.sleep(TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS * 1000);

        ByteBuffer decryptedBuffer = cut.decryptTimeBased(encryptedBuffer, timeBasedKey);
        System.out.println(new String(decryptedBuffer.array()));
        assertEquals(buffer.array(), decryptedBuffer.array());
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testWithoutSavingPastKey() throws InterruptedException {
        ByteBuffer buffer = ByteBuffer.wrap("foobar".getBytes());
        ByteBuffer encryptedBuffer = cut.encryptTimeBased(buffer);
        assertNotEquals(buffer.array(), encryptedBuffer.array());

        Thread.sleep(TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS * 1000);

        ByteBuffer decryptedBuffer = cut.decryptTimeBased(encryptedBuffer);
        System.out.println(new String(decryptedBuffer.array()));
        assertEquals(buffer.array(), decryptedBuffer.array());
    }

    private Key createKey(byte[] newKey) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] keyDigest = md.digest(newKey);
        return new SecretKeySpec(keyDigest, "AES");
    }

    /**
     * This test was taken from the TimeBased project to understand how to use the classes.
     *
     * @throws GeneralSecurityException
     * @throws InterruptedException
     */
    public void testTOTP() throws GeneralSecurityException, InterruptedException {
        String base32Secret = "NY4A5CPJZ46LXZCP";

        System.out.println("secret = " + base32Secret);

        // this is the name of the key which can be displayed by the authenticator program
        String keyId = "user@j256.com";
        // generate the QR code
        System.out.println("Image url = " + TimeBasedOneTimePasswordUtil.qrImageUrl(keyId, base32Secret));
        // we can display this image to the user to let them load it into their auth program

        // we can use the code here and compare it against user input
        String code = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(base32Secret);

		/*
		 * this loop shows how the number changes over time
		 */
        while (true) {
            long diff = TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS
                    - ((System.currentTimeMillis() / 1000) % TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS);
            code = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(base32Secret);
            System.out.println("Secret code = " + code + ", change in " + diff + " seconds");
            Thread.sleep(1000);
        }
    }

    private String expectedCurrentNumber() throws GeneralSecurityException {
        BaseEncoding baseEncoding = BaseEncoding.base32();
        String pass = baseEncoding.encode(createKey(secret.getBytes()).getEncoded());
        return TimeBasedOneTimePasswordUtil.generateCurrentNumberString(pass);
    }

}
