package com.ageid;

public class Derived {

  private byte[] key;
  private byte[] iv;

  public Derived(byte[] key, byte[] iv) {
    this.key = key;
    this.iv = iv;
  }

  public byte[] getKey() {
    return this.key.clone();
  }

  public byte[] getIv() {
    return this.iv.clone();
  }
}
