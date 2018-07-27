package com.cenfotec.encriptacion;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.cenfotec.data.ALGType;
import com.cenfotec.data.DataEncryptManager;
import com.cenfotec.encriptacion.fabrica.Encryptor;

public class SymetricEncrypt implements Encryptor{
	private final int KEYSIZE = 8;
	private final String KEY_EXTENSION = ".key";
	private final String PATH = "C:/encrypt/symetric/";
	private final String ALG = String.valueOf(ALGType.AES);
	
	private DataEncryptManager dataManager;
	
	public void createKey(String name) throws Exception {
		byte [] key = generatedSequenceOfBytes();
		dataManager.writeBytesFile(name,key,KEY_EXTENSION, PATH);
	}

	public void encryptMessage(String messageName, String message, String keyName) throws Exception {
		byte[] key = readKeyFile(keyName);
		SecretKeySpec k = new SecretKeySpec(key, ALG);		
		Cipher cipher = Cipher.getInstance(ALG);
		cipher.init(Cipher.ENCRYPT_MODE, k);
		dataManager.encryptData(messageName, message, cipher, PATH);
	}
	
	public void decryptMessage(String messageName, String keyName) throws Exception {
		byte[] key = readKeyFile(keyName);
		SecretKeySpec k = new SecretKeySpec(key,ALG);
		Cipher cipher = Cipher.getInstance(ALG);
		cipher.init(Cipher.DECRYPT_MODE, k);
		dataManager.decodeData(messageName, cipher, PATH);
	}
	
	private byte[] readKeyFile(String keyName) throws FileNotFoundException, IOException {
		BufferedReader br = new BufferedReader(new FileReader(PATH + keyName + KEY_EXTENSION));
		String everything = "";
		try {
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();

		    while (line != null) {
		        sb.append(line);
		        line = br.readLine();
		    }
		    everything = sb.toString();
		} finally {
		    br.close();
		}
		return everything.getBytes(StandardCharsets.UTF_8);
	}

	private byte[] generatedSequenceOfBytes() throws Exception {
		StringBuilder randomkey = new StringBuilder();
		for (int i = 0;i < KEYSIZE;i++){
			randomkey.append(Integer.parseInt(Double.toString((Math.random()+0.1)*1000).substring(0,2)));
		}
		return randomkey.toString().getBytes("UTF-8");
	}
}
