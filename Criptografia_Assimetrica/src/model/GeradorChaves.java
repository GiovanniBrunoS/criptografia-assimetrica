package model;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GeradorChaves {
	
	private PrivateKey chavePrivada;
    private PublicKey chavePublica;

    public GeradorChaves() {
        KeyPairGenerator gerador = null;
		try {
			gerador = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
        gerador.initialize(512);
        KeyPair chaves = gerador.generateKeyPair();
        this.chavePrivada = chaves.getPrivate();
        this.chavePublica = chaves.getPublic();
    }

    public PrivateKey getChavePrivada() {
        return chavePrivada;
    }

    public PublicKey getChavePublica() {
        return chavePublica;
    }
}
