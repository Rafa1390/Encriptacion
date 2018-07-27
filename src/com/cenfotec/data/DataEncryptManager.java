package com.cenfotec.data;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class DataEncryptManager {
	private final String MESSAGE_ENCRYPT_EXTENSION = ".encript";
	
	public void encryptData(String messageName, String message, Cipher cipher, String PATH)throws IllegalBlockSizeException, BadPaddingException, FileNotFoundException, IOException {
		byte[] encryptedData = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
	    Encoder oneEncoder = Base64.getEncoder();
	    encryptedData = oneEncoder.encode(encryptedData);
		writeBytesFile(messageName,encryptedData,MESSAGE_ENCRYPT_EXTENSION, PATH);
	}
	
	public void writeBytesFile(String name, byte[] content, String type, String PATH) throws FileNotFoundException, IOException {
		FileOutputStream fos = new FileOutputStream(PATH + name + type);
		fos.write(content);
		fos.close();
	}
	
	public void decodeData(String messageName, Cipher cipher, String PATH)throws Exception, IllegalBlockSizeException, BadPaddingException {
		byte[] encryptedMessage = readMessageFile(messageName, PATH);
		byte[] decryptedData = cipher.doFinal(encryptedMessage);
	    String message = new String(decryptedData,StandardCharsets.UTF_8);
	    System.out.println("El mensaje era: ");
		System.out.println(message);
	}
	
	public byte[] readMessageFile(String messageName, String PATH) throws Exception{
		File file = new File(PATH + messageName + MESSAGE_ENCRYPT_EXTENSION);
        int length = (int) file.length();
        BufferedInputStream reader = new BufferedInputStream(new FileInputStream(file));
        byte[] bytes = new byte[length];
        reader.read(bytes, 0, length);
        Decoder oneDecoder = Base64.getDecoder();
	    reader.close();
		return oneDecoder.decode(bytes);
	}
}
