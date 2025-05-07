package burp;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class GsAes {

    /**
     * AES 加密方法
     *
     * @param plainText  明文
     * @param base64Key  密钥（Base64 编码）
     * @param base64Iv   IV（Base64 编码，仅对非 ECB 模式有效）
     * @param mode       AES 模式，包含模式、填充方式和位数（如 AES/CBC/PKCS5Padding/128）
     * @return 加密后的 Base64 编码字符串
     * @throws Exception
     */
    public static String encrypt(String plainText, String base64Key, String base64Iv, String mode) throws Exception {
        String[] modeParts = mode.split("/");
        String algorithm = modeParts[0];  // "AES"
        String cipherMode = modeParts[1]; // "CBC"
        String padding = modeParts[2];    // "PKCS5Padding"
        int keySize = Integer.parseInt(modeParts[3]); // "128" -> 128

        String fullMode = algorithm + "/" + cipherMode + "/" + padding;

        // 解码 Base64 密钥和 IV
        byte[] key = Base64.getDecoder().decode(base64Key);
        byte[] iv = Base64.getDecoder().decode(base64Iv);

        SecretKeySpec k = new SecretKeySpec(padKey(key, keySize), "AES");

        Cipher cipher = Cipher.getInstance(fullMode);

        if (cipherMode.equals("ECB")) {
            cipher.init(Cipher.ENCRYPT_MODE, k);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, k, ivSpec);
        }

        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * AES 解密方法
     *
     * @param base64Cipher Base64 编码的密文
     * @param base64Key    密钥（Base64 编码）
     * @param base64Iv     IV（Base64 编码，仅对非 ECB 模式有效）
     * @param mode         AES 模式，包含模式、填充方式和位数（如 AES/CBC/PKCS5Padding/128）
     * @return 解密后的明文字符串
     * @throws Exception
     */
    public static String decrypt(String base64Cipher, String base64Key, String base64Iv, String mode) throws Exception {
        String[] modeParts = mode.split("/");
        String algorithm = modeParts[0];  // "AES"
        String cipherMode = modeParts[1]; // "CBC"
        String padding = modeParts[2];    // "PKCS5Padding"
        int keySize = Integer.parseInt(modeParts[3]); // "128" -> 128

        String fullMode = algorithm + "/" + cipherMode + "/" + padding;

        // 解码 Base64 密钥和 IV
        byte[] key = Base64.getDecoder().decode(base64Key);
        byte[] iv = Base64.getDecoder().decode(base64Iv);

        SecretKeySpec k = new SecretKeySpec(padKey(key, keySize), "AES");

        Cipher cipher = Cipher.getInstance(fullMode);

        if (cipherMode.equals("ECB")) {
            cipher.init(Cipher.DECRYPT_MODE, k);
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, k, ivSpec);
        }

        byte[] decoded = Base64.getDecoder().decode(base64Cipher);
        byte[] plain = cipher.doFinal(decoded);
        return new String(plain, StandardCharsets.UTF_8);
    }

    /**
     * 填充密钥至指定位数
     *
     * @param key     原始密钥
     * @param keySize 密钥位数（128, 192, 256）
     * @return 填充后的密钥
     */
    private static byte[] padKey(byte[] key, int keySize) {
        byte[] result = new byte[keySize / 8];  // 根据密钥位数设置数组大小
        System.arraycopy(key, 0, result, 0, Math.min(key.length, result.length));
        return result;
    }
}
