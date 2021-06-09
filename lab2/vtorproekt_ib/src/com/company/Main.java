package com.company;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.util.Date;
import java.util.Base64;

class User{
    public String kek;
    public String id;
    public byte[] nonce;
    public String y_ab;
    public String key_ses;

    public User(String kek, String id){
        this.kek=kek;
        this.id=id;
    }
    public byte[] generateNonce(){
        nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public void accept(String y_a,String y_b,String id_bob) throws Exception {
        AES a=new AES();

        String s=a.doDecryption(y_a,kek);
        String [] niza=s.split(" ");
        //verifikacija na nonce-ot
        if(niza[1].equals(Base64.getEncoder().encodeToString(nonce))){
            System.out.println("Dobivme isto nonce!");
        }
        else
        System.out.println("Dobivme razlicno nonce!");

        //verifikacija na id_bob
        if(niza[3].equals(id_bob)){
            System.out.println("Dobivme isto id za bob!");
        }
        else
            System.out.println("Dobivme razlicno id za bob!");

        System.out.println("Dobivme lifetime "+niza[2]);

        //generiranje timestamp
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        System.out.println(timestamp);

        String y_ab_pom=id+" "+timestamp;
        y_ab=a.doEncryption(y_ab_pom,niza[0]);

        key_ses=niza[0];

    }

    public int accept2(String y_b,String y_ab) throws Exception {
        AES a=new AES();

        String s=a.doDecryption(y_b,kek);
        String [] niza=s.split(" ");

        key_ses=niza[0];

        String s2=a.doDecryption(y_ab,niza[0]);
        String [] niza2=s2.split(" ");


        //verifikacija na id_alice
        if(niza[1].equals(niza2[0])){
            System.out.println("Dobivme isto id za alice!");
        }
        else
            System.out.println("Dobivme razlicno id za alice!");

        System.out.println("Dobivme lifetime "+niza[2]);

        //verifikacija na timestamp-ot
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());

        String[] vreme1=niza2[2].split(":");
        float sekundi1=Float.parseFloat(vreme1[0])+Float.parseFloat(vreme1[1])+Float.parseFloat(vreme1[2]);

        String[] vreme2_pom=timestamp.toString().split(" ");
        String[] vreme2=vreme2_pom[1].split(":");
        float sekundi2=Float.parseFloat(vreme2[0])+Float.parseFloat(vreme2[1])+Float.parseFloat(vreme2[2]);

        if(sekundi2-sekundi1<Float.parseFloat(niza[2])*60){
            System.out.println("Ne pominalo vremeto od koga Alice napravila time stamp!");
        }
        else {
            System.out.println("Pominalo vremeto od koga Alice napravila time stamp, sesiskiot kluc ne e validen za koristenje!");
            return 0;
        }
        return 1;
    }

    public String send() throws Exception {
        AES a=new AES();
        String s=a.doEncryption("Ova e nekoja tajna!!!",key_ses);
        return s;
    }

    public String receive(String cipher) throws Exception {
        AES a=new AES();
        String s=a.doDecryption(cipher,key_ses);
        return s;
    }

}

class KDCServer{
    public String kekA;
    public String kekB;
    byte[] keyses;
    public String y_a;
    public String y_b;
    public String T;

    public KDCServer(){
        kekA="aliceskey!!!!!!!";
        kekB="bobskey!!!!!!!!!";
    }

    public void acceptRQST(String idA,String idB, byte[] nonce) throws Exception {
        System.out.println("Serverot gi proveruva id-ata na Alice i Bob...");
        System.out.println("Okej, toa se validni korisnici!");

        //generiranje sesiski kluc so nonce-ot na Alice i nejziniot kluc od bazata
        System.out.println("Generiranje na sesiski kluc...");
        AES a=new AES();
        keyses = new byte[16];
        keyses=a.doEncryption(Base64.getEncoder().encodeToString(nonce),kekA).getBytes();

        //generiranje na T lifetime
        T="0.01"; //30 minuti

        String y_a_pom=Base64.getEncoder().encodeToString(keyses)+" "+Base64.getEncoder().encodeToString(nonce)+" "+T+" "+idB;
        System.out.println(y_a_pom);
        y_a=a.doEncryption(y_a_pom,kekA);

        String y_b_pom=Base64.getEncoder().encodeToString(keyses)+" "+idA+" "+T;
        y_b=a.doEncryption(y_b_pom,kekB);

        System.out.println("Do Alice se prakat "+y_a+" i "+y_b);
    }


}


public class Main {

    public static void main(String[] args) throws Exception {
        User alice=new User("aliceskey!!!!!!!","iamalice");
        User bob=new User("bobskey!!!!!!!!!","iambob");

        byte [] nonce=alice.generateNonce();

        KDCServer kdcServer=new KDCServer();
        kdcServer.acceptRQST(alice.id,bob.id,nonce);

        alice.accept(kdcServer.y_a,kdcServer.y_b,bob.id);

       // Thread.sleep(10000);
        int br=bob.accept2(kdcServer.y_b,alice.y_ab);

        if(br==1) {
            String cipher = alice.send();
            String plain = bob.receive(cipher);
            System.out.println("Bob ja dobi porakata od Alice: " + plain);
        }
        else
            System.out.println("Pomina vremeto na klucot, treba povtorno da se ostvari konekcijata za Bob da dobie poraka od Alice.");
        // write your code here

    }
}
