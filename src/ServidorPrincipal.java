

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.Calendar;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.jcajce.provider.symmetric.Blowfish;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class ServidorPrincipal {
	
	private static final String IP_MAQUINA = "localhost";
	
	public static final String SALUDO = "HOLA";
	public static final String R_OK = "OK";
	public static final String R_ERROR = "ERROR";
	private static final Logger LOGGER = Logger.getLogger("Logger_Servidor");
	private static final String STAMP = "=SERVIDOR=: ";
	private static final String R = "Se ha recibido: ";
	
	//Algoritmos
	public static final String AES = "AES";
	public static final String BLOWFISH = "BlowFish";
	public static final String RSA = "RSA";
	public static final String HMACMD5 = "HMACMD5";
	public static final String HMACSHA1 = "HMACSHA1";
	public static final String HMACSHA256 = "HMACSHA256";
		
	public static void enviarCertificado(PrintWriter out) throws Exception {

		X509Certificate certificadoCliente = GeneradorDeCertificados.crearCertificado(GeneradorDeCertificados.recuperarLlavesDeArchivo(GeneradorDeCertificados.SERVIDOR));
		byte[] certificadoEnBytes = certificadoCliente.getEncoded();
		String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
		out.println(certificadoEnString);
	}
	
	public static void main(String[] args) throws IOException {
		
		ServerSocket listener = new ServerSocket(9090);
		try {		
			
			
			//Creaci�n del socket, del writer y del reader
			Socket socket = listener.accept();
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			
			//Saludo
			boolean saludo = false;
			while(!saludo) {
				String mensaje = in.readLine();
				LOGGER.log(Level.INFO, STAMP +  R + mensaje);
				if(mensaje==null || mensaje.isEmpty()) {
					LOGGER.log(Level.INFO, STAMP + "No se recibi� ning�n mensaje");
				}else {
					if(mensaje.equals(SALUDO)) {
						LOGGER.log(Level.INFO, STAMP + R_OK);
						out.println(R_OK);
						saludo = true;
					}
				}
			}
			
			//Algoritmo
			boolean alg = false;
			String algoritmo = "";
			while(!alg) {
				String recibido = in.readLine();
				if(recibido == null || recibido.isEmpty()) {
					LOGGER.log(Level.INFO, STAMP + "No se ha recibido ning�n mensaje");
				}else{
					algoritmo = recibido;
					LOGGER.log(Level.INFO, STAMP + "El algoritmo recibido fue " + recibido);
					out.println(R_OK);
					alg = true;
				}
			}
			
			//Recibiendo el certificado
			String certificadoRecibido = in.readLine();
			PublicKey llavePublicaCliente = GeneradorDeCertificados.recuperarLlavePublica("./data/clientek+.key");
			
			GeneradorDeCertificados.verificarCertificado(certificadoRecibido, llavePublicaCliente);
			LOGGER.log(Level.INFO, "Se ha verificado el certificado del usuario correctamente");
			
			enviarCertificado(out);
			
			
			//Encriptaci�n del mensaje
			BlowfishEngine bfe = new BlowfishEngine();

			

		}catch(Exception e){
			e.printStackTrace();
		}finally {
			listener.close();
		}
	}
}
