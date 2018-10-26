import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import java.security.spec.InvalidKeySpecException;
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
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public class GeneradorDeCertificados {

	public final static String SERVIDOR = "servidor";

	public final static String CLIENTE = "cliente";
	
	public final static String BASE_PATH = "./data/";

	private static final Logger LOGGER = Logger.getLogger("Logger_Certificados");
	
	private final static Provider bcProvider = new BouncyCastleProvider();


	/**
	 * 
	 * @param duenio
	 * @param llavePublica
	 * @param llavePrivada
	 */
	public static void guardarLlaves(String duenio, Key llavePublica, Key llavePrivada) 
	{
		FileWriter out = null;
		FileWriter out2 = null;
		try {
			String outFile = "./data/" + duenio + "k+" + ".key"; 
			out = new FileWriter(outFile);
			PEMWriter writerPublicKey = new PEMWriter(out);
			writerPublicKey.writeObject(new PemObject("publicKey"+duenio,llavePublica.getEncoded()));

			String outFile2 = "./data/" + duenio + "k-" + ".key"; 
			out2 = new FileWriter(outFile2);
			PEMWriter writerPrivateKey = new PEMWriter(out2);
			writerPrivateKey.writeObject(new PemObject("privateKey"+duenio, llavePrivada.getEncoded()));

			writerPublicKey.close();
			writerPrivateKey.close();

		} catch (Exception e) {
			LOGGER.log(Level.WARNING, "No se pudo guardar las llaves");
			e.printStackTrace();
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
	
	/**
	 * 
	 * @return
	 */
	public static KeyPair generarLlaves() {

		KeyPairGenerator kpg = null;
		KeyPair kp = null;
		try{
			kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			kp = kpg.generateKeyPair();
			LOGGER.info("RSA key pair generated.");
		}

		catch(NoSuchAlgorithmException e){
			LOGGER.log(Level.WARNING, "No se pudo generar las llaves, mal algoritmo");
		}

		return kp;

	}

	/**
	 * 
	 * @param duenio
	 * @return
	 */
	public static KeyPair recuperarLlavesDeArchivo(String duenio) {	

		
		KeyPair llaves = null;
		
		try {
			KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
			
			PrivateKey priv = recuperarLlavePrivada(factory, BASE_PATH + duenio + "k-.key");
			PublicKey pub = recuperarLlavePublica(factory, BASE_PATH + duenio + "k+.key");
			

			llaves = new KeyPair(pub, priv);
			LOGGER.info("Se han recuperado las llaves de " + duenio);
			
			
		} catch (Exception e) {
			e.printStackTrace();
			LOGGER.log(Level.WARNING, "No es posible cargar las llaves");
		}


		return llaves;
	}
	
	/**
	 * 
	 * @param factory
	 * @param filename
	 * @return
	 * @throws InvalidKeySpecException
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private static PrivateKey recuperarLlavePrivada(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(filename)));
				
		byte[] content = pemReader.readPemObject().getContent();
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
		return factory.generatePrivate(privKeySpec);
	}
	
	/**
	 * Método encargado de recuperar la llave publica de un archivo PEM dado por parametro. 
	 * @param factory
	 * @param filename
	 * @return
	 * @throws InvalidKeySpecException
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private static PublicKey recuperarLlavePublica(KeyFactory factory, String filename) throws InvalidKeySpecException, FileNotFoundException, IOException {
		PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(filename)));	
		
		byte[] content = pemReader.readPemObject().getContent();
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
		return factory.generatePublic(pubKeySpec);
	}

	/**
	 * 
	 * @param keyPair
	 * @param subjectDN
	 * @return
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static X509Certificate crearCertificado(KeyPair keyPair, String subjectDN) throws OperatorCreationException, CertificateException, IOException
	{
		Security.addProvider(bcProvider);	
		LOGGER.info("BouncyCastle provider added.");

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

		Security.addProvider(bcProvider);	
		
		KeyPair llavesGeneradasCliente = generarLlaves();
		KeyPair llavesGeneradasServidor = generarLlaves();

		guardarLlaves("cliente", llavesGeneradasCliente.getPublic(), llavesGeneradasCliente.getPrivate());
		guardarLlaves("servidor", llavesGeneradasServidor.getPublic(), llavesGeneradasServidor.getPrivate());

		try {
			// Recuperación de llaves
			KeyPair llavesCliente = recuperarLlavesDeArchivo(CLIENTE);
			KeyPair llavesServidor = recuperarLlavesDeArchivo(SERVIDOR);
		

			//Certificados
			X509Certificate certificadoCliente = crearCertificado(llavesCliente, "autenticar");
			X509Certificate certificadoServidor = crearCertificado(llavesServidor, "autenticar");

			File archivoCliente = new File("./data/certificadoCliente");
			PemWriter writerCliente = new PemWriter(new FileWriter(archivoCliente));
			writerCliente.writeObject(new PemObject("CERTIFICATE", certificadoCliente.getEncoded()));

			File archivoServidor = new File("./data/certificadoServidor");
			PemWriter writerServidor = new PemWriter(new FileWriter(archivoServidor));
			writerServidor.writeObject(new PemObject("CERTIFICATE", certificadoServidor.getEncoded()));



		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}

	}
}
