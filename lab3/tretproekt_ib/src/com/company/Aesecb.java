package com.company;//package com.company;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;


import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

class AES {

    private static final String ALGORITHM       = "AES";
    private static final String myEncryptionKey = "ThisIsFoundation";
    private static final String UNICODE_FORMAT  = "UTF8";
    private static SecretKey secretKey;
    private static byte[] key;

        public static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes(StandardCharsets.UTF_8);
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    public static String encrypt(String valueToEnc, String key) throws Exception {
            setKey(key);
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encValue = c.doFinal(valueToEnc.getBytes(UNICODE_FORMAT));
        String encryptedValue = Base64.getEncoder().encodeToString(encValue);
        return encryptedValue;
    }

    public static String decrypt(String encryptedValue, String key) throws Exception {
        setKey(key);
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decordedValue = Base64.getDecoder().decode(encryptedValue);
        byte[] decValue = c.doFinal(decordedValue);//////////LINE 50
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }

    private static Key generateKey() throws Exception {
        byte[] keyAsBytes;
        keyAsBytes = myEncryptionKey.getBytes(UNICODE_FORMAT);
        Key key = new SecretKeySpec(keyAsBytes, ALGORITHM);
        return key;
    }

    public static void main(String[] args) throws Exception {

        String value = "YdrVnrKa7xPbacN0LDYcsQ==";
        String valueEnc = AES.encrypt(value,"kkk");
        String valueDec = AES.decrypt(valueEnc,"kkk");

        System.out.println("Plain Text : " + value);
        System.out.println("Encrypted : " + valueEnc);
        System.out.println("Decrypted : " + valueDec);
    }

}