package com.cenfotec.encriptacion.fabrica;

import com.cenfotec.encriptacion.AsymetricEncrypt;
import com.cenfotec.encriptacion.SymetricEncrypt;

public class EncryptFactory {
	public static Encryptor create(int pOption) {
		switch(pOption) {
		case 1:
			return new AsymetricEncrypt();
		case 2:
			return new SymetricEncrypt();
		default:
			return null;
		}
	}
}
