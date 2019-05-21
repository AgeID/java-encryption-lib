package com.ageid;

import com.ageid.EncryptionHelper.AgeidVersion;
import org.junit.Assert;
import org.junit.Test;

public class EncryptionHelperTest {

  @Test
  public void v1TestEncrypt() {
    String password = "UyBr4VkvZgR1uS";
    String salt = "1c4dd21d7ba43bdd";
    String text = "text clear";
    String expectedHash = "eyJzYWx0IjoiTVdNMFpHUXlNV1EzWW1FME0ySmtaQT09IiwiZW5jcnlwdGVkIjoiWktjTWxCQVN5OFBBckNxMzVNTGRHQT09IiwibWFjIjoiZjZjMTRmNWUzOTEzMGRiMDczMTI3M2I1ZTcwY2NhNmNlZjliMGUwZjkzYmVlMThmNmFmOGI3MGE4MGZmYTk2ZSJ9";
    EncryptionHelper encryptionHelper = new EncryptionHelper(password, salt, AgeidVersion.v1);
    String hash = encryptionHelper.encrypt(text);
    Assert.assertEquals(hash, expectedHash);
  }

  @Test
  public void v1TestDecrypt() {
    String password = "UyBr4VkvZgR1uS";
    String salt = "1c4dd21d7ba43bdd";
    String expectedText = "text clear";
    String hash = "eyJzYWx0IjoiTVdNMFpHUXlNV1EzWW1FME0ySmtaQT09IiwiZW5jcnlwdGVkIjoiWktjTWxCQVN5OFBBckNxMzVNTGRHQT09IiwibWFjIjoiZjZjMTRmNWUzOTEzMGRiMDczMTI3M2I1ZTcwY2NhNmNlZjliMGUwZjkzYmVlMThmNmFmOGI3MGE4MGZmYTk2ZSJ9";
    EncryptionHelper encryptionHelper = new EncryptionHelper(password, salt, AgeidVersion.v1);
    String text = encryptionHelper.decrypt(hash);
    Assert.assertEquals(text, expectedText);
  }

  @Test
  public void v2TestEncrypt() {
    String expectedHash = "eyJzYWx0IjoiWVdKalpHVm1aMmhwYW10c2JXNXZjSEZ5YzNSMWRuZDRlWHBCUWtORVJVWkhTRWxLUzB4TlRrOVFVVkpUVkZWV1YxaFpXakF4TWpNME5UWTNPRGs9IiwiZW5jcnlwdGVkIjoibDY4dFJUc1NLeVdNRHFwR2xQWlM5dz09IiwibWFjIjoiM2VjYmY5MzliMmE1YjQxYmU0MWQwNTc0OTVhNjIxYTk5YTNlZjg4NmFkNTRkNTEwNWEyZmUwMWQ0NTA0YjJiYiJ9";
    EncryptionHelper encryptionHelper = new EncryptionHelper(
        "someText",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        AgeidVersion.v2
    );
    String hash = encryptionHelper.encrypt("somePass");
    Assert.assertEquals(hash, expectedHash);
  }

  @Test
  public void v2TestEncryptEmptyText(){
    String expectedHash = "eyJzYWx0IjoiVW1veUwyUk5OVmhhT0ZGVWRYY3ZXakpTZW1wRVVUMDkiLCJlbmNyeXB0ZWQiOiJEMzdzcFlPV1IrMmFRbFZSVzMxMGNBPT0iLCJtYWMiOiI3N2UwZTU3MjMwNjRiYWI5YzUwZjlmODcyZjkwNDBkZDFiMDY5OTU4MjM0NTJjZjNhNTFhMDJlM2EzMTNmNDJmIn0=";
    EncryptionHelper encryptionHelper = new EncryptionHelper(
        "someText",
        "Rj2/dM5XZ8QTuw/Z2RzjDQ==",
        AgeidVersion.v2
    );
    String hash = encryptionHelper.encrypt("");
    Assert.assertEquals(hash, expectedHash);
  }

  @Test
  public void v2TestEncryptAlphaNumericText(){
    String expectedHash = "eyJzYWx0IjoiVW1veUwyUk5OVmhhT0ZGVWRYY3ZXakpTZW1wRVVUMDkiLCJlbmNyeXB0ZWQiOiJ4RTQ0Q1EvY3FBc3JwQ3lyZ0JRSXZLeEh5YjhEcUNpbjRKNnF1aFdwKzFTSkN2eXpGNThJZnpaYVkwV3N2ODhadGpBT29nRkJPMFZ2ZzhzUll5N3g3dz09IiwibWFjIjoiYWFhNDgwNWVhMWQ5NDMwZmMzMjJkMGNiODY2ODlmYTI0NGYwNjJlYmIyZWMzM2FlNjlkNDYwMzAxNDRiZjI4ZSJ9";
    EncryptionHelper encryptionHelper = new EncryptionHelper(
        "someText",
        "Rj2/dM5XZ8QTuw/Z2RzjDQ==",
        AgeidVersion.v2
    );
    String hash = encryptionHelper.encrypt("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    Assert.assertEquals(hash, expectedHash);
  }

  @Test
  public void v2TestEncryptWithAlphaNumericSalt(){
    String expectedHash = "eyJzYWx0IjoiWVdKalpHVm1aMmhwYW10c2JXNXZjSEZ5YzNSMWRuZDRlWHBCUWtORVJVWkhTRWxLUzB4TlRrOVFVVkpUVkZWV1YxaFpXakF4TWpNME5UWTNPRGs9IiwiZW5jcnlwdGVkIjoibDY4dFJUc1NLeVdNRHFwR2xQWlM5dz09IiwibWFjIjoiM2VjYmY5MzliMmE1YjQxYmU0MWQwNTc0OTVhNjIxYTk5YTNlZjg4NmFkNTRkNTEwNWEyZmUwMWQ0NTA0YjJiYiJ9";
    EncryptionHelper encryptionHelper = new EncryptionHelper(
        "someText",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        AgeidVersion.v2
    );
    String hash = encryptionHelper.encrypt("somePass");
    Assert.assertEquals(hash, expectedHash);
  }

  @Test
  public void v2TestEncryptFullTextRange(){
    String expectedHash = "eyJzYWx0IjoiVW1veUwyUk5OVmhhT0ZGVWRYY3ZXakpTZW1wRVVUMDkiLCJlbmNyeXB0ZWQiOiJ4RTQ0Q1EvY3FBc3JwQ3lyZ0JRSXZLeEh5YjhEcUNpbjRKNnF1aFdwKzFTSkN2eXpGNThJZnpaYVkwV3N2ODhaMXN3QmJwcGRudzlRbVd4c2duTXo2aTUvYVZicDFPbmQ2cHhDNFBEN0VWcnV3Q1RDa3ViUXRCRGtwR0FrY1lJbSIsIm1hYyI6ImMzMjExNTA4MGUyZTgyODc1ZGI5YjNmMTg4ODQ4ZDI0OGYxZGVmMDFhMWE3NTY0MmIwZDhmNjM5YzExMjllM2MifQ==";
    EncryptionHelper encryptionHelper = new EncryptionHelper(
        "someText",
        "Rj2/dM5XZ8QTuw/Z2RzjDQ==",
        AgeidVersion.v2
    );
    String hash = encryptionHelper.encrypt("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`-=[]\\;',./~!@#$%^&*()_+{}|:\"<>?");
    Assert.assertEquals(hash, expectedHash);
  }

  @Test
  public void v2TestEncryptWithFullRangePassword(){
    String expectedHash = "eyJzYWx0IjoiVW1veUwyUk5OVmhhT0ZGVWRYY3ZXakpTZW1wRVVUMDkiLCJlbmNyeXB0ZWQiOiJDOHV5Q3FrcFM5L29ZVGJ1TmtiUHFRPT0iLCJtYWMiOiI0OTQyM2RiOGFhZGZmYjJiNWNmMDFmZDNjNzAyNGFmNTRlMWVjMDkyYjFlY2JhNGVlMzQwODAzYWVjYTA0MmE5In0=";
    EncryptionHelper encryptionHelper = new EncryptionHelper(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`-=[]\\;',./~!@#$%^&*()_+{}|:\"<>?",
        "Rj2/dM5XZ8QTuw/Z2RzjDQ==",
        AgeidVersion.v2
    );
    String hash = encryptionHelper.encrypt("somePass");
    Assert.assertEquals(hash, expectedHash);
  }

  @Test
  public void v2TestEncryptWithFullRangeSalt(){
    String expectedHash = "eyJzYWx0IjoiWVdKalpHVm1aMmhwYW10c2JXNXZjSEZ5YzNSMWRuZDRlWHBCUWtORVJVWkhTRWxLUzB4TlRrOVFVVkpUVkZWV1YxaFpXakF4TWpNME5UWTNPRGxnTFQxYlhWdzdKeXd1TDM0aFFDTWtKVjRtS2lncFh5dDdmWHc2SWp3K1B3PT0iLCJlbmNyeXB0ZWQiOiJRc3NrRXBBN1c2YjlsOHg1c3A3K1JnPT0iLCJtYWMiOiIyMmM2NzkzZWFjYjI5OGM0YjI2N2NhYzdkMjgzZDc1YzcwNGJkOGU3NDI5MmZjOGE2NTZkODU0MGJlMWY5NjM0In0=";
    EncryptionHelper encryptionHelper = new EncryptionHelper(
        "someText",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`-=[]\\;',./~!@#$%^&*()_+{}|:\"<>?",
        AgeidVersion.v2
    );
    String hash = encryptionHelper.encrypt("somePass");
    Assert.assertEquals(hash, expectedHash);
  }

  @Test
  public void v2TestEncryptDecryptNoSalt(){
    EncryptionHelper encryptionHelper = new EncryptionHelper(
        "someText",
        null,
        AgeidVersion.v2
    );
    String hash = encryptionHelper.encrypt("somePass");
    String decrypted = encryptionHelper.decrypt(hash);
    Assert.assertEquals("somePass", decrypted);
  }

  @Test
  public void v2TestDecrypt() {
    String hash = "eyJzYWx0IjoiWVdKalpHVm1aMmhwYW10c2JXNXZjSEZ5YzNSMWRuZDRlWHBCUWtORVJVWkhTRWxLUzB4TlRrOVFVVkpUVkZWV1YxaFpXakF4TWpNME5UWTNPRGs9IiwiZW5jcnlwdGVkIjoibDY4dFJUc1NLeVdNRHFwR2xQWlM5dz09IiwibWFjIjoiM2VjYmY5MzliMmE1YjQxYmU0MWQwNTc0OTVhNjIxYTk5YTNlZjg4NmFkNTRkNTEwNWEyZmUwMWQ0NTA0YjJiYiJ9";
    EncryptionHelper encryptionHelper = new EncryptionHelper(
        "someText",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        AgeidVersion.v2
    );
    String text = encryptionHelper.decrypt(hash);
    Assert.assertEquals(text, "somePass");
  }
}
