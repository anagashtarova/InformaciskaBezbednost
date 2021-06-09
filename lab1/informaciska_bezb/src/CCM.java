import org.w3c.dom.css.Counter;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.lang.Object;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

class Header{
    public String source_mac;
    public String destination_mac;
    public String qos;

    public Header(String source_mac,String destination_mac, String qos) {
        this.source_mac=source_mac;
        this.destination_mac=destination_mac;
        this.qos=qos;
    }
}

class ClearTextFrame {
    public int pn;
    public Header frame_header;
    public String data;


    public ClearTextFrame(Header frame_header, int pn, String data) {
        this.data = data;
        this.frame_header = frame_header;
        this.pn = pn;
    }

}

class EncryptedFrame {
    public int pn;
    public Header frame_header;
    public String data;
    public String MIC;
    public byte[] nonce;
    public byte[] aad;

    public EncryptedFrame(Header frame_header, int pn,String data) {
        this.frame_header = frame_header;
        this.pn = pn;
        this.data=data;

        nonce = new byte[String.valueOf(pn + 1).getBytes().length + frame_header.source_mac.getBytes().length + frame_header.qos.getBytes().length];
        System.arraycopy(String.valueOf(pn + 1).getBytes(), 0, nonce, 0, String.valueOf(pn + 1).getBytes().length);
        System.arraycopy(frame_header.source_mac.getBytes(), 0, nonce, String.valueOf(pn + 1).getBytes().length, frame_header.source_mac.getBytes().length);
        System.arraycopy(frame_header.qos.getBytes(), 0, nonce, frame_header.source_mac.getBytes().length, frame_header.qos.getBytes().length);

        aad = new byte[frame_header.source_mac.length() + frame_header.destination_mac.length()+frame_header.qos.length()];
        System.arraycopy(frame_header.source_mac.getBytes(), 0, aad, 0, frame_header.source_mac.length());
        System.arraycopy(frame_header.destination_mac.getBytes(), 0, aad, frame_header.source_mac.length(), frame_header.destination_mac.length());
        System.arraycopy(frame_header.qos.getBytes(), 0, aad, frame_header.destination_mac.length(), frame_header.qos.length());

    }

    public byte[][] divideArray(byte[] source) {


        byte[][] ret = new byte[(int) Math.ceil(source.length / (double) 16)][16];

        int start = 0;

        for (int i = 0; i < ret.length; i++) {
            if (start + 16 > source.length) {
                System.arraycopy(source, start, ret[i], 0, source.length - start);
            } else {
                System.arraycopy(source, start, ret[i], 0, 16);
            }
            start += 16;
        }

        return ret;
    }

    public byte[][] ccmaes() throws Exception {

        byte[][] podatoci = divideArray(data.getBytes());
        int counter = 0;
        byte[][] xorovana = new byte[podatoci.length][16];

        AES a = new AES();

        byte[] enc = new byte[16];
        byte[] ctr;

        for (int i = 0; i < podatoci.length; i++) {
            ctr = new byte[nonce.length + String.valueOf(counter + 1).length()];
            System.arraycopy(nonce, 0, ctr, 0, nonce.length);
            System.arraycopy(String.valueOf(counter + 1).getBytes(), 0, ctr, nonce.length, String.valueOf(counter + 1).length());


            enc = a.doEncryption(Base64.getEncoder().encodeToString(ctr), "thisisthekey!!!!").getBytes();
            counter++;

            byte[] pom = new byte[16];

            for (int j = 0; j < 16; j++) {
                pom[j] = (byte) (enc[j] ^ podatoci[i][j]);
            }
            xorovana[i] = pom;

        }
        return xorovana;

    }

    public byte[] ccmaes2() throws Exception {

        byte[][] podatoci = divideArray(data.getBytes());
        //byte[][] xorovana = new byte[podatoci.length][16];
        byte[][] header = divideArray(aad);

        AES a = new AES();

        byte[] enc = new byte[16];
        byte[] mic=new byte[8];
        byte[] ctr;
        byte[] ctr_encrypted;

        enc = a.doEncryption(Base64.getEncoder().encodeToString(nonce), "thisisthekey!!!!").getBytes();

        for (int i = 0; i < header.length; i++) {
            byte[] pom = new byte[16];

            for (int j = 0; j < 16; j++) {
                pom[j] = (byte) (enc[j] ^ header[i][j]);
            }
            //    xorovana[i] = pom;
            enc=a.doEncryption(Base64.getEncoder().encodeToString(pom),"thisisthekey!!!!").getBytes();
        }

        for (int i = 0; i < podatoci.length; i++) {
            byte[] pom = new byte[16];

            for (int j = 0; j < 16; j++) {
                pom[j] = (byte) (enc[j] ^ podatoci[i][j]);
            }
            //    xorovana[i] = pom;
            enc=a.doEncryption(Base64.getEncoder().encodeToString(pom),"thisisthekey!!!!").getBytes();
        }

        for(int i=0;i<enc.length;i++){
            if(i==8) break;
            mic[i]=enc[i];
        }

        ctr = new byte[nonce.length + String.valueOf(0).length()];
        System.arraycopy(nonce, 0, ctr, 0, nonce.length);
        System.arraycopy(String.valueOf(0).getBytes(), 0, ctr, nonce.length, String.valueOf(0).length());

        ctr_encrypted = a.doEncryption(Base64.getEncoder().encodeToString(ctr), "thisisthekey!!!!").getBytes();

        byte[] ctr_encrypted_64=new byte[8];

        for(int i=0;i<ctr_encrypted.length;i++){
            if(i==8) break;
            ctr_encrypted_64[i]=ctr_encrypted[i];
        }

        byte[] mic_final = new byte[8];

        for (int j = 0; j < 8; j++) {
            mic_final[j] = (byte) (ctr_encrypted_64[j] ^ mic[j]);
        }

        return mic_final;

    }

    //delot za dekripcija-----------------------------------------------------------------------

    public byte[][] ccmaes_d(byte[][] podatoci) throws Exception {

//        byte[][] podatoci = divideArray(enc_data);
        int counter = 0;
        byte[][] xorovana = new byte[podatoci.length][16];

        AES a = new AES();

        byte[] enc = new byte[16];
        byte[] ctr;

        for (int i = 0; i < podatoci.length; i++) {
            ctr = new byte[nonce.length + String.valueOf(counter + 1).length()];
            System.arraycopy(nonce, 0, ctr, 0, nonce.length);
            System.arraycopy(String.valueOf(counter + 1).getBytes(), 0, ctr, nonce.length, String.valueOf(counter + 1).length());

            enc = a.doEncryption(Base64.getEncoder().encodeToString(ctr), "thisisthekey!!!!").getBytes();
            counter++;

            byte[] pom = new byte[16];

            for (int j = 0; j < 16; j++) {
                pom[j] = (byte) (enc[j] ^ podatoci[i][j]);
            }
            xorovana[i] = pom;
        }
        return xorovana;

    }

    public byte[] ccmaes2_d(byte [][] podatoci) throws Exception {

        //byte[][] xorovana = new byte[podatoci.length][16];
        byte[][] header = divideArray(aad);

        AES a = new AES();

        byte[] enc = new byte[16];
        byte[] mic=new byte[8];
        byte[] ctr;
        byte[] ctr_encrypted;

        enc = a.doEncryption(Base64.getEncoder().encodeToString(nonce), "thisisthekey!!!!").getBytes();

        for (int i = 0; i < header.length; i++) {
            byte[] pom = new byte[16];

            for (int j = 0; j < 16; j++) {
                pom[j] = (byte) (enc[j] ^ header[i][j]);
            }
            //    xorovana[i] = pom;
            enc=a.doEncryption(Base64.getEncoder().encodeToString(pom),"thisisthekey!!!!").getBytes();
        }

        for (int i = 0; i < podatoci.length; i++) {
            byte[] pom = new byte[16];

            for (int j = 0; j < 16; j++) {
                pom[j] = (byte) (enc[j] ^ podatoci[i][j]);
            }
            //    xorovana[i] = pom;
            enc=a.doEncryption(Base64.getEncoder().encodeToString(pom),"thisisthekey!!!!").getBytes();
        }

        for(int i=0;i<enc.length;i++){
            if(i==8) break;
            mic[i]=enc[i];
        }

        ctr = new byte[nonce.length + String.valueOf(0).length()];
        System.arraycopy(nonce, 0, ctr, 0, nonce.length);
        System.arraycopy(String.valueOf(0).getBytes(), 0, ctr, nonce.length, String.valueOf(0).length());

        ctr_encrypted = a.doEncryption(Base64.getEncoder().encodeToString(ctr), "thisisthekey!!!!").getBytes();

        byte[] ctr_encrypted_64=new byte[8];

        for(int i=0;i<ctr_encrypted.length;i++){
            if(i==8) break;
            ctr_encrypted_64[i]=ctr_encrypted[i];
        }

        byte[] mic_final = new byte[8];

        for (int j = 0; j < 8; j++) {
            mic_final[j] = (byte) (ctr_encrypted_64[j] ^ mic[j]);
        }

        return mic_final;

    }

}


public class CCM {
    public static void main(String[] args) throws Exception {
        Header header=new Header("sourcemacadd","destinationmac","one");
        ClearTextFrame clearTextFrame=new ClearTextFrame(header,1,"This is a big secret!0000000000000000000");
        System.out.println("Kreirame ramka so text: "+clearTextFrame.data);

        EncryptedFrame encryptedFrame=new EncryptedFrame(header,1,"This is a big secret!");

        byte [][] rez = encryptedFrame.ccmaes();
        System.out.println("Go enkriptirame tekstot i presmetuvame mic pred da ja ispratime ramkata...");

        for(int i=0;i<rez.length;i++)
            System.out.println("Enkriptiraniot tekst e: "+Base64.getEncoder().encodeToString(rez[i]));

        byte [] mic = encryptedFrame.ccmaes2();
        System.out.println("Mic-ot ispraten so ramkata e: "+Base64.getEncoder().encodeToString(mic));

        System.out.println("Ja isprakjame ramkata so enkriptiran text i mic...");

        byte [][] plain = encryptedFrame.ccmaes_d(rez);
        StringBuilder dektiptiran = new StringBuilder();
        for(int i=0;i<plain.length;i++)
            dektiptiran.append(new String(plain[i], StandardCharsets.UTF_8));

        System.out.println("Dekriptiraniot tekst e: "+dektiptiran);

        byte[] mic_od_dekriptiran_text = new byte[8];

        try {
            mic_od_dekriptiran_text = encryptedFrame.ccmaes2_d(plain);

            System.out.println("Mic-ot dobien so dekriptiraniot text od ramkata e: " + Base64.getEncoder().encodeToString(mic_od_dekriptiran_text));
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        if(!Arrays.equals(mic,mic_od_dekriptiran_text)){
            throw new Exception("Razlicen mic dobien!!!");
        }
        if(Arrays.equals(mic,mic_od_dekriptiran_text)){
            System.out.println("Dobivme ist MIC, znaci se e vo red so paketot!");
        }

    }

}
