package sample;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Cell;
import javafx.stage.Stage;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;

public class Sender extends Application {

    public String absolutePath = "C:\\Users\\BAHI\\IdeaProjects\\Security_Project_1\\" ;
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
        while(true)
        {
            try {
                SecretKey dsa_orignal_Key = new SecretKeySpec(key, 0, key.length, "DES");

                byte[] data = des_decrypt(dsa_orignal_Key, cipher);
                if (new String(data).equals(plane))
                    return key;
            }
            catch (Exception e)
            {

            }

            if(key[0]==127)
            {for(int i=1;i<8;i++)
            {
                if(key[i]==127)
                {
                    key[i]++;
                }
                else
                {
                    key[i]++;
                    break;
                }
            }
            }


            key[0]++;

        }


    }

    public  void plotBruteForce(Stage stage) throws Exception
    {

        //plot
        stage.setTitle("BruteForce");
        //defining the axes
        final NumberAxis xAxis = new NumberAxis();
        final NumberAxis yAxis = new NumberAxis();
        xAxis.setLabel("Length");
        yAxis.setLabel("Total Time (Ms)");
        //creating the chart
        final LineChart<Number,Number> lineChart =
                new LineChart<Number,Number>(xAxis,yAxis);


        //defining a series
        XYChart.Series series = new XYChart.Series();
        series.setName("Points");
        String message="hello there!";

        for (int i = 8; i <= 32; i += 8) {
            SecretKey DESKey = buildSecretkey(i);
            byte [] encrypted_message = des_encrypt(DESKey,message);
            long startTime = System.nanoTime();
            bruteForce(message,encrypted_message);
            long endTime = System.nanoTime();
            long totalTime = endTime - startTime;
            series.getData().add(new XYChart.Data(i , totalTime/1000000));


        }

        Scene scene  = new Scene(lineChart,800,600);
        lineChart.getData().add(series);

        stage.setScene(scene);
        stage.show();
    }

    public static byte[] readBytesFromFile(File file) throws IOException {
        InputStream is = new FileInputStream(file);

        // Get the size of the file
        long length = file.length();

        // You cannot create an array using a long type.
        // It needs to be an int type.
        // Before converting to an int type, check
        // to ensure that file is not larger than Integer.MAX_VALUE.
        if (length > Integer.MAX_VALUE) {
            throw new IOException("Could not completely read file " + file.getName() + " as it is too long (" + length + " bytes, max supported " + Integer.MAX_VALUE + ")");
        }

        // Create the byte array to hold the data
        byte[] bytes = new byte[(int)length];

        // Read in the bytes
        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length && (numRead=is.read(bytes, offset, bytes.length-offset)) >= 0) {
            offset += numRead;
        }

        // Ensure all the bytes have been read in
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + file.getName());
        }

        // Close the input stream and return bytes
        is.close();
        return bytes;
    }



    public  void SendEmailSSL(String messageBody)
    {
        String username = "bahi.ali26196@gmail.com";
        String password = "creldrdxqqnxgdaa";

        Properties prop = new Properties();

        prop.put("mail.smtp.host", "smtp.gmail.com");
        prop.put("mail.smtp.port", "465");
        prop.put("mail.smtp.auth", "true");
        prop.put("mail.smtp.socketFactory.port", "465");
        prop.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");


        Session session = Session.getInstance(prop,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });

        try {

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(
                    Message.RecipientType.TO,
                    InternetAddress.parse("yasminalaa161195@gmail.com")
            );
            message.setSubject("Testing Gmail TLS");
            message.setText(messageBody);

            Transport.send(message);

            System.out.println("Done");

        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void start(Stage primaryStage) throws Exception
    {
        System.out.println("1-encrypt a message.\n2-brute force attack.\n3-exit");
        Scanner scanner1 = new Scanner(System. in);
        int op=scanner1.nextInt();
        if(op==1)
        {
            SecretKey DESKey = buildSecretkey(56);
            File file1 = new File("RSAKEY.txt");

            byte[] RSAPublic = readBytesFromFile(file1);
            PublicKey publicKey =
                    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(RSAPublic));
            System.out.print("Enter email body : ");
            Scanner scanner = new Scanner(System.in);
            String message = scanner.nextLine();
            //encryption
            byte[] enc = DESKey.getEncoded();
            byte[] encrypted_message = des_encrypt(DESKey, message);
            byte[] session = rsa_encrypt(publicKey, enc);
            String s1 = Base64.getEncoder().encodeToString(session);
            String s2 = Base64.getEncoder().encodeToString(encrypted_message);


            byte[] data = Base64.getDecoder().decode(s2);
            //System.out.println(s2);

            SendEmailSSL(s1 + "Break" + s2);
        }
        else
            if(op==2)
                plotBruteForce(primaryStage);
            else
                System.exit(0);
    }



    public static void main(String[] args) {
        launch(args);
    }
}
