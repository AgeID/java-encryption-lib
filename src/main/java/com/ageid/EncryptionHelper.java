package com.ageid;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONException;
import org.json.JSONObject;

public class EncryptionHelper {

  public enum AgeidVersion {
    v1(32768), v2(1024);

    private int iterations;

    AgeidVersion(int iterations) {
      this.iterations = iterations;
    }

    public int getIterations() {
      return this.iterations;
    }
  }

  private String password;
  private String salt;
  private int iterations;

  public EncryptionHelper(String password, String salt) {
    this.password = password;
    this.salt = salt;
    this.iterations = AgeidVersion.v2.getIterations();
  }

  public EncryptionHelper(String password, String salt, AgeidVersion version) {
    this.password = password;
    this.salt = salt;
    this.iterations = version.getIterations();
  }

  private String hash(String salt, String value) throws AgeIdException {
    Mac sha256_HMAC;

    try {
      sha256_HMAC = Mac.getInstance("HmacSHA256");
      SecretKeySpec pass = new SecretKeySpec(this.password.getBytes("UTF-8"), "HmacSHA256");
      sha256_HMAC.init(pass);
      return HexBin.encode(sha256_HMAC.doFinal((salt + value).getBytes("UTF-8"))).toLowerCase();
    } catch (NoSuchAlgorithmException e) {
      throw new AgeIdException("hash generation error", e);
    } catch (InvalidKeyException e) {
      throw new AgeIdException("hash generation error", e);
    } catch (UnsupportedEncodingException e) {
      throw new AgeIdException("hash generation error", e);
    }
  }

  private String AESEncryptBytes(String text, String pass, String salt) {
    try {
      Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(pass, salt, this.iterations);
      Derived derived = rfc2898DeriveBytes.derived();
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
      IvParameterSpec iv = new IvParameterSpec(derived.getIv());
      SecretKeySpec skeySpec = new SecretKeySpec(derived.getKey(), "AES");
      cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

      byte[] encryptedBytes = cipher.doFinal(text.getBytes());
      return Base64.encode(encryptedBytes);
    } catch (GeneralSecurityException e) {
      throw new AgeIdException("encryption error", e);
    }
  }

  private String AESDecryptBytes(byte[] crypto, String pass, String salt) {
    try {
      Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(pass, salt, this.iterations);
      Derived derived = rfc2898DeriveBytes.derived();
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      IvParameterSpec iv = new IvParameterSpec(derived.getIv());
      SecretKeySpec skeySpec = new SecretKeySpec(derived.getKey(), "AES");
      cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
      byte[] encryptedBytes = cipher.doFinal(crypto);
      return new String(encryptedBytes, "UTF-8");
    } catch (GeneralSecurityException e) {
      throw new AgeIdException("decryption error", e);
    } catch (UnsupportedEncodingException e) {
      throw new AgeIdException("decryption error", e);
    }
  }

  public String encrypt(String text) throws AgeIdException {
    String saltString;
    if (this.salt == null) {
      byte[] array = new byte[8];
      new Random().nextBytes(array);
      try {
        saltString = new String(array, "UTF-8");
      } catch (UnsupportedEncodingException e) {
        throw new AgeIdException("random salt generation error", e);
      }
    } else {
      saltString = this.salt;
    }
    String encrypted = AESEncryptBytes(text, this.password, saltString);
    String salt = Base64.encode(saltString.getBytes());
    String mac = this.hash(salt, encrypted);

    Map<String, String> jsonMap = new LinkedHashMap<String, String>();
    jsonMap.put("salt", salt);
    jsonMap.put("encrypted", encrypted);
    jsonMap.put("mac", mac);
    JSONObject json = new JSONObject(jsonMap);
    return Base64.encode(json.toString().getBytes());
  }

  public String decrypt(String source) throws AgeIdException {

    String jsonString;
    JSONObject json;
    try {
      jsonString = new String(Base64.decode(source), "UTF-8");
      json = new JSONObject(jsonString);

      //test payload
      String inSaltBase64 = json.get("salt").toString();
      String inMac = json.get("mac").toString();
      String inEncryptedBase64 = json.get("encrypted").toString();
      String mac = this.hash(inSaltBase64, inEncryptedBase64);
      if (!inMac.equals(mac)) {
        throw new AgeIdException("invalid mac");
      }

      //concrete decryption of supplied string
      String salt = new String(Base64.decode(inSaltBase64), "UTF-8");
      byte[] encrypted = Base64.decode(inEncryptedBase64);
      return this.AESDecryptBytes(encrypted, this.password, salt);
    } catch (JSONException e) {
      throw new AgeIdException("decryption error", e);
    } catch (UnsupportedEncodingException e) {
      throw new AgeIdException("decryption error", e);
    }
  }
}
