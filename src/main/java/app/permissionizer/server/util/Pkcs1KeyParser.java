package app.permissionizer.server.util;

import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Pkcs1KeyParser {

    public static PrivateKey parsePem(Path path) {
        try {
            return parsePem(Files.readString(path), path.toString());
        } catch (IOException e) {
            throw new RuntimeException("Failed to read private key file %s: %s".formatted(path, e.getMessage()), e);
        }
    }

    public static PrivateKey parsePem(String pem, String source) {
        try {
            var key = pem
                    .replaceAll("-----.+KEY-----", "")
                    .replaceAll("\\s+", "");

            var bytes = Base64.getDecoder().decode(key);
            bytes = buildPkcs8KeyFromPkcs1Key(bytes);
            var keyFactory = KeyFactory.getInstance("RSA");
            var keySpec = new PKCS8EncodedKeySpec(bytes);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("Failed to parse private key from %s: %s".formatted(source, e.getMessage()), e);
        }
    }

    private static byte[] buildPkcs8KeyFromPkcs1Key(byte[] innerKey) {
        var result = new byte[innerKey.length + 26];
        System.arraycopy(Base64.getDecoder().decode("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKY="), 0, result, 0, 26);
        System.arraycopy(BigInteger.valueOf(result.length - 4).toByteArray(), 0, result, 2, 2);
        System.arraycopy(BigInteger.valueOf(innerKey.length).toByteArray(), 0, result, 24, 2);
        System.arraycopy(innerKey, 0, result, 26, innerKey.length);
        return result;
    }
}
