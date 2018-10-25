import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Date;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class GeneradorDeCertificados {

	private static final Logger LOGGER = Logger.getLogger("Logger_Certificados");


	public static void guardarLlaves(String duenio, Key llavePublica, Key llavePrivada) 
	{
		FileOutputStream out = null;
		FileOutputStream out2 = null;
		try {
			String outFile = "./data/" + duenio + "k+" + ".key"; 
			out = new FileOutputStream(outFile);
			out.write(llavePublica.getEncoded());

			String outFile2 = "./data/" + duenio + "k-" + ".key"; 
			out2 = new FileOutputStream(outFile2);
			out.write(llavePrivada.getEncoded());

		} catch (Exception e) {
			LOGGER.log(Level.WARNING, "No se pudo guardar las llaves");
		} finally {

			try{
				out.close();
				out2.close();
			}
			catch(Exception e){
				LOGGER.log(Level.WARNING, e.getMessage());
			}
		}

	}

	public static KeyPair generarLlaves() {

		KeyPairGenerator kpg = null;
		KeyPair kp = null;
		try{
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			kp = kpg.generateKeyPair();
		}

		catch(NoSuchAlgorithmException e){
			LOGGER.log(Level.WARNING, "No se pudo generar las llaves, mal algoritmo");
		}

		return kp;

	}

	public static X509Certificate crearCertificado(KeyPair keyPair, String subjectDN) throws OperatorCreationException, CertificateException, IOException
	{
		Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);

		long now = System.currentTimeMillis();
		Date startDate = new Date(now);

		X500Name dnName = new X500Name(subjectDN);
		BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity

		Date endDate = (Date) calendar.getTime();

		String signatureAlgorithm = "SHA256WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.

		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

		// Extensions --------------------------

		// Basic Constraints
		BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

		certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

		// -------------------------------------

		return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
	}	

	public static void main(String[] args) {
			
//		KeyPair llavesGeneradasCliente = generarLlaves();
//		KeyPair llavesGeneradasServidor = generarLlaves();
//		
//		guardarLlaves("cliente", llavesGeneradasCliente.getPublic(), llavesGeneradasCliente.getPrivate());
//		guardarLlaves("servidor", llavesGeneradasCliente.getPublic(), llavesGeneradasCliente.getPrivate());
//		System.out.println("terminé");
		
		try {
			//Cliente
			
			KeyFactory kf = KeyFactory.getInstance("RSA");
			
			// Llaves del cliente
			File fClientePub = new File("./data/clientek+.key");
			byte[] bytesClientePub = Files.readAllBytes(fClientePub.toPath());
			X509EncodedKeySpec ksClientePub = new X509EncodedKeySpec(bytesClientePub);
			PublicKey keyClientpub = kf.generatePublic(ksClientePub);
			
	
			File fClientePriv = new File("./data/clientek-.key");
			byte[] bytesClientePriv = Files.readAllBytes(fClientePriv.toPath());
			PKCS8EncodedKeySpec ksClientePriv = new PKCS8EncodedKeySpec(bytesClientePriv);
			PrivateKey keyClientPriv = kf.generatePrivate(ksClientePriv);
			
			
			
			
			// Llaves del servidor
			File fServidorPub = new File("./data/servidork+.key");
			byte[] bytesServidorPub = Files.readAllBytes(fServidorPub.toPath());
			X509EncodedKeySpec ksServidorPub = new X509EncodedKeySpec(bytesServidorPub);
			PublicKey keyServidorPub = kf.generatePublic(ksServidorPub);
			
			
			
			File fServidorPriv = new File("./data/servidork-.key");
			byte[] bytesServidorPriv = Files.readAllBytes(fServidorPriv.toPath());
			PKCS8EncodedKeySpec ksServidorPriv = new PKCS8EncodedKeySpec(bytesServidorPriv);
			PrivateKey keyServidorPriv = kf.generatePrivate(ksServidorPriv);
			
			
			KeyPair kpCliente = new KeyPair(keyClientpub, keyClientPriv);
			KeyPair kpServidor = new KeyPair(keyServidorPub, keyServidorPriv);
			
			
			// Certificados
			X509Certificate certificadoCliente = crearCertificado(kpCliente, "autenticar");
			X509Certificate certificadoServidor = crearCertificado(kpServidor, "autenticar");
			
			File archivoCliente = new File("./data/certificadoCliente");
			PemWriter writerCliente = new PemWriter(new FileWriter(archivoCliente));
			writerCliente.writeObject(new PemObject("CERTIFICATE", certificadoCliente.getEncoded()));
			
			File archivoServidor = new File("./data/certificadoServidor");
			PemWriter writerServidor = new PemWriter(new FileWriter(archivoServidor));
			writerServidor.writeObject(new PemObject("CERTIFICATE", certificadoServidor.getEncoded()));
			
		} catch (Exception e) {
			// TODO: handle exception
		}

	}
}
