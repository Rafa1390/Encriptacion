package com.cenfotec.encriptacion;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.cenfotec.data.ALGType;
import com.cenfotec.data.DataEncryptManager;
import com.cenfotec.encriptacion.fabrica.Encryptor;

public class AsymetricEncrypt implements Encryptor{
	private final String KEY_EXTENSION = ".key";
	private final String PUBLIC = "public";
	private final String PRIVATE = "private";
	private final String PATH = "C:/encrypt/asymetric/";
	
	private final String ALG = String.valueOf(ALGType.RSA);//new
	private DataEncryptManager dataManager = new DataEncryptManager();//new
	
	public void createKey(String name) throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALG);
		KeyFactory fact = KeyFactory.getInstance(ALG);
		kpg.initialize(2048);
		KeyPair kp = kpg.genKeyPair();
		RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(),
		  RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(),
		  RSAPrivateKeySpec.class);

		saveToFile(PATH + name+"public.key", pub.getModulus(),
		  pub.getPublicExponent());
		saveToFile(PATH + name+"private.key", priv.getModulus(),
		  priv.getPrivateExponent());
	}
	
	public void saveToFile(String fileName,BigInteger mod, BigInteger exp) throws IOException {
		ObjectOutputStream oout = new ObjectOutputStream(
			    new BufferedOutputStream(new FileOutputStream(fileName)));
		try {
			oout.writeObject(mod);
			oout.writeObject(exp);
		} catch (Exception e) {
			throw new IOException("Unexpected error", e);
		} finally {
		    oout.close();
		}
	}

	public void encryptMessage(String messageName, String message, String keyName) throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException{
		PublicKey pubKey = (PublicKey)readKeyFromFile(keyName, PUBLIC);
		Cipher cipher = Cipher.getInstance(ALG);
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		dataManager.encryptData(messageName, message, cipher, PATH);
	}
	
	public void decryptMessage(String messageName, String keyName) throws Exception {
		PrivateKey privKey = (PrivateKey)readKeyFromFile(keyName, PRIVATE);
		Cipher cipher = Cipher.getInstance(ALG);
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		dataManager.decodeData(messageName, cipher, PATH);
	}
	
	Key readKeyFromFile(String keyFileName, String type) throws IOException {
		  InputStream in = new FileInputStream (PATH + keyFileName+ type + KEY_EXTENSION);
		  ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
		  try {
		    BigInteger m = (BigInteger) oin.readObject();
		    BigInteger e = (BigInteger) oin.readObject();
		    if (type.equals("public")) {
			    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
			    KeyFactory fact = KeyFactory.getInstance(ALG);
			    PublicKey pubKey = fact.generatePublic(keySpec);
			    return pubKey;		    	
		    } else {
		    	RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
			    KeyFactory fact = KeyFactory.getInstance(ALG);
			    PrivateKey pubKey = fact.generatePrivate(keySpec);
			    return pubKey;		    	
		    }
		  } catch (Exception e) {
		    throw new RuntimeException("Spurious serialisation error", e);
		  } finally {
		    oin.close();
		  }
		}
}
