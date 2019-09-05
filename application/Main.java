package application;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import model.Codificador;
import model.Decodificador;
import model.GeradorChaves;

public class Main {

	public static void main(String[] args) {

		GeradorChaves geradorChaves = new GeradorChaves();
		Codificador codificador = new Codificador();
		Decodificador decodificador = new Decodificador();

		String chavePublica = Base64.getEncoder().encodeToString(geradorChaves.getChavePublica().getEncoded());
		String chavePrivada = Base64.getEncoder().encodeToString(geradorChaves.getChavePrivada().getEncoded());

		System.out.println("Chave Publica: " + chavePublica);
		System.out.println("Chave Privada: " + chavePrivada);
		System.out.println();

		Scanner ler = new Scanner(System.in);
		System.out.println("Digite uma mensagem para ser criptografada: ");
		String mensagemCriptografar = ler.nextLine();

		ler.close();

		String mensagemPublica = mensagemCriptografar;
		String mensagemPrivada = mensagemCriptografar;

		try {
			mensagemPublica = codificador.criptografarChavePublica(mensagemPublica, chavePublica);
			mensagemPrivada = codificador.criptografarChavePrivada(mensagemPrivada, chavePrivada);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}

		System.out.println();
		System.out.println("Mensagem codificada com chave Publica: " + mensagemPublica);
		System.out.println("Mensagem codificada com chave Privada: " + mensagemPrivada);

		try {
			mensagemPublica = decodificador.descriptografarChavePrivada(mensagemPublica, chavePrivada);
			mensagemPrivada = decodificador.descriptografarChavePublica(mensagemPrivada, chavePublica);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
				| NoSuchPaddingException e) {
			e.printStackTrace();
		}

		System.out.println();
		System.out
				.println("Mensagem codificada com chave publica e descodificada com chave privada: " + mensagemPublica);
		System.out
				.println("Mensagem codificada com chave privada e descodificada com chave publica: " + mensagemPrivada);
	}
}
