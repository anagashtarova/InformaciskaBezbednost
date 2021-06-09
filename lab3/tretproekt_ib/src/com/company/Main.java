package com.company;

import java.security.*;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.Map;
import java.util.Random;

class Alice{
    int alpha;
    PrivateKey private_key;
    PublicKey public_key;
    int alpha_x;
    int x;
    int key;

    public Alice(int alpha) throws Exception {
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(4096);
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        private_key = keyPair.getPrivate();
//        public_key = keyPair.getPublic();

        Asymmetric asymmetric=new Asymmetric();
        Map<String, Object> keys = Asymmetric.getRSAKeys();
        private_key = (PrivateKey) keys.get("private");
        public_key = (PublicKey) keys.get("public");


        this.alpha=alpha;
        Random rand = new Random();
        x = rand.nextInt(5);
        System.out.println(x);
    }

    public int send(){
        System.out.println("Alice sends the number she generated (alpha^x)... to Bob");
        System.out.println(alpha);

        int pr=1;

        for(int i=0;i<x;i++) {
            pr *= alpha;
        }
        System.out.println(alpha);
        alpha_x=pr;
        return alpha_x;
    }

    public String receive(int broj, String kriptirano, PublicKey publicKey) throws Exception {
        int p=1;
        for(int i=0;i<x;i++)
            p*=broj;

        key=p;

        System.out.println("Klucot kaj Alice "+key);

        AES a=new AES();

        System.out.println("Alice go primi paketot od Bob i go dekriptira i go presmetuva klucot...");

        //SMENI
        Asymmetric A=new Asymmetric();
        String dobieno = AES.decrypt(kriptirano,String.valueOf(key));

        System.out.println(dobieno);

        String str= Asymmetric.decryptMessage(dobieno,publicKey);

        String [] niza=str.split(" ");

        if(String.valueOf(broj).compareTo(niza[0])==0){
            System.out.println("Dobivme ista vrednost za alpha^y");
        }
        if(String.valueOf(alpha_x).compareTo(niza[1])==0){
            System.out.println("Dobivme ista vrednost za alpha^x");
        }

        String s = Asymmetric.encryptMessage(alpha_x+" "+broj,private_key);

        String prati = AES.encrypt(s,String.valueOf(key));

        System.out.println("Alice isprakja enkriptirana so zaednickiot kluc i so privatniot kluc poraka od alpha^x i alpha^y...");

        return prati;

    }

}

class Bob{
    int alpha;
    PrivateKey private_key;
    PublicKey public_key;
    int alpha_y;
    int y;
    int key;
    int alpha_x;

    public Bob(int alpha) throws Exception {
        this.alpha=alpha;

//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(4096);
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        private_key = keyPair.getPrivate();
//        public_key = keyPair.getPublic();

        Asymmetric asymmetric=new Asymmetric();
        Map<String, Object> keys = Asymmetric.getRSAKeys();
        private_key = (PrivateKey) keys.get("private");
        public_key = (PublicKey) keys.get("public");

        Random rand = new Random();
        y = rand.nextInt(5);
        System.out.println(y);
    }

    public String receive(int broj) throws Exception {
        int br=broj;
        alpha_x=broj;

        System.out.println("Bob received the number Alice generated (alpha^x) "+alpha_x+"...");

        int pr=1;
        for(int i=0;i<y;i++) {
            pr *= alpha;
        }
        alpha_y=pr;

        int p=1;
        for(int i=0;i<y;i++) {
            p *= broj;
          }
        key=p;

        System.out.println("Klucot kaj Bob "+key);

        AES a=new AES();

        Asymmetric A=new Asymmetric();

        //SMENI

        String s = Asymmetric.encryptMessage(alpha_y+" "+br,private_key);

        System.out.println(s);

        System.out.println(String.valueOf(key));
        String prati = AES.encrypt(s,String.valueOf(key));

        System.out.println("Bob sends Alice the number he generated (alpha^y)...");
        System.out.println("Bob isprakja i enkriptirana so zaednickiot kluc i so privatniot kluc poraka od alpha^x i alpha^y...");

        return prati;
    }


    public void primi(String primi, PublicKey publicKey) throws Exception {

        AES a=new AES();
        Asymmetric A=new Asymmetric();

        String dobieno = AES.decrypt(primi,String.valueOf(key));

        String str= Asymmetric.decryptMessage(dobieno,publicKey);

        String [] niza=str.split(" ");

        if(String.valueOf(alpha_y).compareTo(niza[1])==0){
            System.out.println("Dobivme ista vrednost za alpha^y");
        }
        if(String.valueOf(alpha_x).compareTo(niza[1])==0){
            System.out.println("Dobivme ista vrednost za alpha^x");
        }

    }


}


public class Main {

    public static void main(String[] args) throws Exception {
        Alice alice=new Alice(2);
        Bob bob=new Bob(2);

        int br1=alice.send();
        String prati =bob.receive(br1);

        String prati2 =alice.receive(bob.alpha_y,prati,bob.public_key);
        bob.primi(prati2,alice.public_key);

    }
}
