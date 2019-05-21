package com.ageid;

public class AgeIdException extends RuntimeException {

  public AgeIdException(String message) {
    super(message);
  }

  public AgeIdException(String message, Throwable cause) {
    super(message, cause);
  }
}
