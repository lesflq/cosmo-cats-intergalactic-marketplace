package org.example.lab1.config.JWT;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class JwtGenerator {

    private final PrivateKey privateKey;

    public JwtGenerator(String privateKeyPath) throws Exception {
        this.privateKey = loadPrivateKey(privateKeyPath);
    }

    private PrivateKey loadPrivateKey(String resourcePath) throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                throw new IllegalArgumentException("Файл не знайдено: " + resourcePath);
            }
            // Читаємо весь PEM-файл
            String pemContent = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);

            // Видаляємо заголовок, підпис та пробіли
            pemContent = pemContent
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            // Декодуємо Base64 у байти
            byte[] keyBytes = Base64.getDecoder().decode(pemContent);

            // Створюємо приватний ключ
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }
    }


    public String generateToken(String subject) throws Exception {
        // Встановлюємо час дії токена
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date expiryDate = new Date(nowMillis + 3600000); // 1 година

        // Створюємо JWT claims
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer("SpaceCatsMarket")
                .expirationTime(expiryDate)
                .issueTime(now)
                .build();

        // Підписуємо токен
        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("c9e57581-a7c2-4af1-ba80-fa9ddd5a0216").build(),
                claimsSet);

        signedJWT.sign(signer);
        return signedJWT.serialize();
    }
}
