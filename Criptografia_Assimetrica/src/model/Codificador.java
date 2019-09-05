package model;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Codificador {

	private PublicKey getChavePublica(String chavePublicaString) {
		PublicKey chavePublica = null;
		try {
			X509EncodedKeySpec chave = new X509EncodedKeySpec(
					Base64.getDecoder().decode(chavePublicaString.getBytes()));
			KeyFactory conversorChave = KeyFactory.getInstance("RSA");
			chavePublica = conversorChave.generatePublic(chave);
			return chavePublica;
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return chavePublica;
	}
	
	private PrivateKey getChavePrivada(String chavePrivadaString){
        PrivateKey chavePrivada = null;
        PKCS8EncodedKeySpec chave = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(chavePrivadaString.getBytes()));
        KeyFactory conversorChave = null;
        try {
            conversorChave = KeyFactory.getInstance("RSA");
            chavePrivada = conversorChave.generatePrivate(chave);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return chavePrivada;
    }

	public String criptografarChavePublica(String mensagem, String chavePublica) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cifra = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cifra.init(Cipher.ENCRYPT_MODE, getChavePublica(chavePublica));
		return Base64.getEncoder().encodeToString(cifra.doFinal(mensagem.getBytes()));
	}

	public String criptografarChavePrivada(String mensagem, String chavePrivada) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cifra = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cifra.init(Cipher.ENCRYPT_MODE, getChavePrivada(chavePrivada));
		return Base64.getEncoder().encodeToString(cifra.doFinal(mensagem.getBytes()));
	}
}
