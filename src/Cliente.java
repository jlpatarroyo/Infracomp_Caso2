
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.DatatypeConverter;


import org.bouncycastle.jce.provider.BouncyCastleProvider;




public class Cliente {


	private static final String IP_MAQUINA = "localhost";
	private static final int PUERTO = 9090;
	private static final Logger LOGGER = Logger.getLogger("Logger_Cliente");
	private static final String STAMP = "=CLIENTE=: ";
	private static final String R = "Se ha recibido: ";

	private BufferedReader in;
	private PrintWriter out;
	private Scanner scanner;

	public void run() {
		try
		{

			Socket socket = new Socket(IP_MAQUINA, PUERTO);
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(socket.getOutputStream(), true);
			scanner = new Scanner(System.in);

			//Saludo
			boolean saludo = false;
			while(!saludo) {
				//Mensaje cliente
				System.out.println("Ingrese un mensaje: ");
				String mensaje = scanner.nextLine();
				LOGGER.log(Level.INFO, STAMP + mensaje);
				out.println(mensaje);
				//Respuesta servidor
				String respuesta = in.readLine();
				if(respuesta==null || respuesta.isEmpty()) {
					LOGGER.log(Level.INFO, STAMP + "No se ha recibido respuesta");
				}else {
					LOGGER.log(Level.INFO, STAMP + R + respuesta);
					saludo = true;
				}
			}

			//Algoritmos
			boolean algoritmo = false;
			while(!algoritmo) {
				System.out.println("Ingrese el algoritmo de cifrado que desea utilizar");
				System.out.println("Puede elegir entre " + ServidorPrincipal.AES + ", " + ServidorPrincipal.BLOWFISH
						+ ", " + ServidorPrincipal.HMACMD5 + ", " + ServidorPrincipal.HMACSHA1 + ", " + 
						ServidorPrincipal.HMACSHA256);
				System.out.println("**Preste atenci�n especial al uso de may�sculas**");
				String mensaje = scanner.nextLine();
				if(mensaje == null || mensaje.isEmpty()) {
					LOGGER.log(Level.WARNING, "Ingrese un mensaje");
				}else {
					//Verificaci�n del algoritmo
					String alg = "";
					if(mensaje.contains(ServidorPrincipal.AES)) {
						alg = ServidorPrincipal.AES;
					}else if(mensaje.contains(ServidorPrincipal.BLOWFISH)) {
						alg = ServidorPrincipal.BLOWFISH;
					}else if(mensaje.contains(ServidorPrincipal.HMACMD5)) {
						alg = ServidorPrincipal.HMACMD5;
					}else if(mensaje.contains(ServidorPrincipal.HMACSHA1)) {
						alg = ServidorPrincipal.HMACSHA1;
					}else if(mensaje.contains(ServidorPrincipal.HMACSHA256)) {
						alg = ServidorPrincipal.HMACSHA256;
					}else {
						LOGGER.log(Level.WARNING, STAMP + "Revise el algoritmo enviado");
					}
					LOGGER.log(Level.INFO, STAMP + "El algoritmo recibido fue " + alg);
					out.println(alg);

					String respuesta = in.readLine();
					if(respuesta.equals(ServidorPrincipal.R_OK)) {
						algoritmo = true;
						LOGGER.log(Level.INFO, R + respuesta);
					}
				}
			}
			
			enviarCertificado(out);

			String certificadoRecibido = in.readLine();
			PublicKey llavePublicaServidor = GeneradorDeCertificados.recuperarLlavePublica("./data/servidork+.key");
			
			GeneradorDeCertificados.verificarCertificado(certificadoRecibido, llavePublicaServidor);
			LOGGER.log(Level.INFO, "Se ha verificado el certificado del servidor correctamente");

			//Terminaci�n
			socket.close();
		}catch(Exception e) {
			e.printStackTrace();
		}
	}

	public static void enviarCertificado(PrintWriter out) throws Exception {

		X509Certificate certificadoCliente = GeneradorDeCertificados.crearCertificado(GeneradorDeCertificados.recuperarLlavesDeArchivo(GeneradorDeCertificados.CLIENTE));
		byte[] certificadoEnBytes = certificadoCliente.getEncoded();
		String certificadoEnString = DatatypeConverter.printHexBinary(certificadoEnBytes);
		out.println(certificadoEnString);
	}


	public static void main(String[] args) {
		Cliente cliente = new Cliente();
		cliente.run();
	}



}
