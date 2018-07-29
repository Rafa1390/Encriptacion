package com.cenfotec.main;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;

import com.cenfotec.encriptacion.fabrica.EncryptFactory;
import com.cenfotec.encriptacion.fabrica.Encryptor;

public class UI {
	static BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
	static PrintStream out = System.out;
	static Encryptor encryptor;
	
	public static void main(String[] args) throws Exception {
		int option = 0;
		do {
    		out.println("Choose the type of encryption that do you want");
        	out.println("1.Asymetric");
        	out.println("2.Symetric");
        	out.println("3.Exit ");
        	option = Integer.parseInt(in.readLine());
        	if (option >= 1 && option <= 2){
        		encryptor = EncryptFactory.create(option);
        		executionMenu();
        	}
    	} while (option != 3);

    	
    }
	
	private static void executionMenu() throws Exception {
		int option = 0;
		do {
    		out.println("1.Create key");
        	out.println("2.Encript Message");
        	out.println("3.Decrypt Message");
        	out.println("4.Exit ");
        	option = Integer.parseInt(in.readLine());
        	if (option >= 1 && option <= 3){
        		executeAction(option);
        	}
    	} while (option != 4);
	}

	private static void executeAction(int option) throws Exception {
		if (option == 1){ 
			out.println("Key name: ");
			String name = in.readLine();
			encryptor.createKey(name);
		}
		if (option == 2){
			out.println("Key name: ");
			String name = in.readLine();
			out.println("Message name: ");
			String messageName = in.readLine();
			out.println("Message: ");
			String message = in.readLine();
			encryptor.encryptMessage(messageName,message,name);
		}
		if (option == 3){
			out.println("Key name: ");
			String keyName = in.readLine();
			out.println("Message name: ");
			String messageName = in.readLine();
			encryptor.decryptMessage(messageName, keyName);			
		}
	}
}
