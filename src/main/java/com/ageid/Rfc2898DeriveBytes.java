package com.ageid;

import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Rfc2898DeriveBytes {

  private char[] password;
  private byte[] salt;
  private int iterations;

  public Rfc2898DeriveBytes(String password, String salt, int iterations) {
    this.password = password.toCharArray();
    this.salt = salt.getBytes();
    this.iterations = iterations;
  }

  public Derived derived() {
    SecretKeyFactory factory;
    int keyLength = 32;
    int ivLength = 16;
    byte[] keyBytes = new byte[keyLength];
    byte[] ivBytes = new byte[ivLength];

    try {
      factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      KeySpec spec = new PBEKeySpec(this.password, this.salt, this.iterations, (keyLength + ivLength) * Byte.SIZE);
      SecretKey secretKey = factory.generateSecret(spec);
      byte[] data = secretKey.getEncoded();
      System.arraycopy(data, 0, keyBytes, 0, keyLength);
      System.arraycopy(data, keyLength, ivBytes, 0, ivLength);
      return new Derived(keyBytes, ivBytes);
    } catch (GeneralSecurityException e) {
      return new Derived(null, null);
    }
  }
}
