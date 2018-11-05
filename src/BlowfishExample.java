
import java.security.*;
import javax.crypto.*;

/**
 *	BlowfishExample.java
 *
 *	This class creates a Blowfish key, encrypts some text,
 *	prints the ciphertext, then decrypts the text and
 *	prints that.
 *
 *	It requires a JCE-compliant Blowfish engine, like Cryptix' JCE.
 *TOMADO DE: https://gist.github.com/tdpauw/be447e2293c4f060ce34
 */
public class BlowfishExample
{
  public static void main (String[] args)
  throws Exception
  {
//    if (args.length != 1) {
//      System.err.println("Usage: java BlowfishExample text");
//      System.exit(1);
//    }
    String text = "Josesito";

    System.out.println("Generating a Blowfish key...");

    // Create a Blowfish key
    KeyGenerator keyGenerator = KeyGenerator.getInstance("Blowfish");
    keyGenerator.init(128);	// need to initialize with the keysize
    Key key = keyGenerator.generateKey();

    System.out.println("Done generating the key.");

    // Create a cipher using that key to initialize it
    Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);

    byte[] plaintext = text.getBytes("UTF8");

    // Print out the bytes of the plaintext
    System.out.println("\nPlaintext: ");
    for (int i=0;i<plaintext.length;i++) {
		System.out.print(plaintext[i]+" ");
	}

    // Perform the actual encryption
    byte[] ciphertext = cipher.doFinal(plaintext);

	// Print out the ciphertext
    System.out.println("\n\nCiphertext: ");
    for (int i=0;i<ciphertext.length;i++) {
		System.out.print(ciphertext[i]+" ");
	}

    // Re-initialize the cipher to decrypt mode
    cipher.init(Cipher.DECRYPT_MODE, key);

    // Perform the decryption
    byte[] decryptedText = cipher.doFinal(ciphertext);

    String output = new String(decryptedText,"UTF8");

    System.out.println("\n\nDecrypted text: "+output);


  }
}