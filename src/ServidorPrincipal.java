import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServidorPrincipal {
	
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
	
	public static void main(String[] args) throws IOException {
		
		ServerSocket listener = new ServerSocket(9090);

		try {
			//Creación del socket, del writer y del reader
			Socket socket = listener.accept();
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			
			//Saludo
			boolean saludo = false;
			while(!saludo) {
				String mensaje = in.readLine();
				LOGGER.log(Level.INFO, STAMP +  R + mensaje);
				if(mensaje==null || mensaje.isEmpty()) {
					LOGGER.log(Level.INFO, STAMP + "No se recibió ningún mensaje");
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
					LOGGER.log(Level.INFO, STAMP + "No se ha recibido ningún mensaje");
				}else{
					algoritmo = recibido;
					LOGGER.log(Level.INFO, STAMP + "El algoritmo recibido fue " + recibido);
					out.println(R_OK);
					alg = true;
				}
			}
			

		}finally {
			listener.close();
		}
	}
}
