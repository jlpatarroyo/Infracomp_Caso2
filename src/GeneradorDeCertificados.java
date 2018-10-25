import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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

public class GeneradorDeCertificados {

	private static final Logger LOGGER = Logger.getLogger("Logger_Certificados");


	public static void guardarLlaves(String duenio, Key llavePublica, Key llavePrivada) 
	{
		FileOutputStream out = null;
		FileOutputStream out2 = null;
		try {
			String outFile = "./data/" + duenio; 
			out = new FileOutputStream(outFile + ".key");
			out.write(llavePublica.getEncoded());

			String outFile2 = "./data/" + duenio; 
			out2 = new FileOutputStream(outFile2 + ".key");
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

		KeyPair llavesGeneradasCliente = generarLlaves();
		KeyPair llavesGeneradasServidor = generarLlaves();
		
		guardarLlaves("cliente", llavesGeneradasCliente.getPublic(), llavesGeneradasCliente.getPrivate());
		guardarLlaves("servidor", llavesGeneradasCliente.getPublic(), llavesGeneradasCliente.getPrivate());
		System.out.println("terminé");

	}
}
