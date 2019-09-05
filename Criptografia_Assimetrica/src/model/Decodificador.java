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

public class Decodificador {
	
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

	private String descriptografarChavePrivada(byte[] mensagem, PrivateKey chavePrivada) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cifra = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cifra.init(Cipher.DECRYPT_MODE, chavePrivada);
        return new String(cifra.doFinal(mensagem));
    }
	
	public String descriptografarChavePrivada(String mensagem, String chavePrivada) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return descriptografarChavePrivada(Base64.getDecoder().decode(mensagem.getBytes()), getChavePrivada(chavePrivada));
    }
	
	private String descriptografarChavePublica(byte[] mensagem, PublicKey chavePublica) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cifra = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cifra.init(Cipher.DECRYPT_MODE, chavePublica);
        return new String(cifra.doFinal(mensagem));
    }
	
	public String descriptografarChavePublica(String mensagem, String chavePublica) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return descriptografarChavePublica(Base64.getDecoder().decode(mensagem.getBytes()), getChavePublica(chavePublica));
    }
}
