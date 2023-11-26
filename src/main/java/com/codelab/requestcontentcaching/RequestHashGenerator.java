package com.codelab.requestcontentcaching;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

import static java.lang.StringTemplate.STR;

public class RequestHashGenerator {
    private static final String secret = "fake-secret";

    private static final Mac mac;

    static {
        String algorithm = "HmacSHA512";
        try {
            mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithm));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static String generateHash(String payload) {
        return Base64.getEncoder().encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8))).trim();
    }

    public static void main(String[] args) {
        var customer = new Customer("John Okafor", UUID.fromString("e1221b65-6027-446e-a4ef-cf8cda75b399"), "+233898232942", "50.50", "2023-11-20T09:23:23Z");
        String payload = STR.
                """
                {
                    "customerName": "\{customer.customerName}",
                    "customerId": "\{customer.customerId}",
                    "customerPhone": "\{customer.customerPhone}",
                    "amount": "\{customer.amount}",
                    "paidAt": "\{customer.paidAt}"
                }""";
        System.out.println(payload);
        var hash = generateHash(payload);
        System.out.println(hash);
    }

    record Customer(String customerName, UUID customerId, String customerPhone, String amount, String paidAt){}

}
