package sample;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Cell;
import javafx.stage.Stage;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class Main extends Application {

    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }
    public static SecretKey buildSecretkey(int size) throws NoSuchAlgorithmException {
        size=size/8;
        byte [] key={0,0,0,0,0,0,0,0};
        byte[] b = new byte[size];
        new Random().nextBytes(b);
        for (int i=0;i<size;++i)
            key[i]=b[i];
        SecretKey dsa_orignal_Key = new SecretKeySpec(key, 0, key.length, "DES");
        //System.out.println(Arrays.toString(key));
        return dsa_orignal_Key;
    }

    public static byte[] rsa_encrypt(PublicKey publicKey, byte [] message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message);
    }

    public static byte[] rsa_decrypt(PrivateKey privateKey, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encrypted);
    }

    public byte [] des_encrypt(SecretKey deskey,String s) throws Exception {
        Cipher DesCipher = Cipher.getInstance("DES");
        DesCipher.init(Cipher.ENCRYPT_MODE, deskey);
        byte[] x=DesCipher.doFinal(s.getBytes());
        return x;
    }
    public byte [] des_decrypt(SecretKey deskey,byte [] x) throws Exception {
        Cipher DesCipher = Cipher.getInstance("DES");
        DesCipher.init(Cipher.DECRYPT_MODE, deskey);
        byte [] s=DesCipher.doFinal(x);
        return s;
    }
    public byte [] bruteForce(String plane,byte [] cipher)
    {
        byte [] key={0,0,0,0,0,0,0,0};
        for (int j=0;j<8;++j)
            for(byte i=-127;i>-128;++i)
            {
                key[j]=i;
                System.out.println(Arrays.toString(key));
                try {
                    SecretKey dsa_orignal_Key = new SecretKeySpec(key, 0, key.length, "DES");

                    byte[] data = des_decrypt(dsa_orignal_Key, cipher);
                    if (new String(data) == plane)
                        return key;
                }
                catch (Exception e)
                {

                }

            }
        return null;
    }
    @Override
    public void start(Stage primaryStage) throws Exception{

        SecretKey DESKey = buildSecretkey(8);
        KeyPair RSAKeys= buildKeyPair();
        String message="hello there!";
        //encryption
        byte [] enc = DESKey.getEncoded();
        byte [] encrypted_message = des_encrypt(DESKey,message);

        byte [] session = rsa_encrypt(RSAKeys.getPublic(),enc);


        //decryption
        byte [] rsa_en=rsa_decrypt(RSAKeys.getPrivate(),session);
        SecretKey dsa_orignal_Key = new SecretKeySpec(rsa_en, 0, rsa_en.length, "DES");
        System.out.println(new String(des_decrypt(dsa_orignal_Key,encrypted_message)));
       // System.out.println(Arrays.toString(DESKey.getEncoded()));
        byte [] out=bruteForce(message,encrypted_message);
        if(out != null)
            System.out.println(out);
        else System.out.println("could'nt break the key");


    }



    public static void main(String[] args) {
        launch(args);
    }
}
