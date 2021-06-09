package com.company;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

class AES {
    public SecretKey secretKey;
    public byte[] key;
    Cipher c;
    public AES() throws Exception {
        //konstruktor

        // kreiranje na cipher object
        c = Cipher.getInstance("AES/ECB/PKCS5Padding");

    }
    public void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
    public String doEncryption(String s,String k) throws Exception {

        setKey(k);
        // inicijalizacija na cipher object-ot
        c.init(Cipher.ENCRYPT_MODE, secretKey);

        //sensitive information
        byte[] text = s.getBytes("UTF-8");

        // enkripcija na text
        byte[] textEncrypted = c.doFinal(text);

        return(Base64.getEncoder().encodeToString(textEncrypted));

    }
    public String doDecryption(String s,String k)throws Exception {

        setKey(k);

        // inicijalizacija na istiot cipher object za dekripcija
        c.init(Cipher.DECRYPT_MODE, secretKey);

        // dekripcija na s nizata
         byte[] textDecrypted = c.doFinal(Base64.getDecoder().decode(s));

        return(new String(textDecrypted));
    }
}

public class Aesecb {

    public static void main(String[] argv) throws Exception {
        AES d=new AES();
        String originalString = "Z2llVjVTV0pkaTd1Q2twVHNkbnhjd2ZraGdGanpqdEZjZUg1ZWo3V3Q3UT0= 4XKS3k4bCGrkAkt9uwv6BQ== 30 bob!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!11!!!!!!!!";
        String k="aliceskey!!!!!!!";
        String str=d.doEncryption(originalString,k);

        System.out.println("Original String : "+originalString);
        System.out.println("Encrypted String : "+str);
        System.out.println("Decrypted String : "+d.doDecryption(str,k));

    }
}
