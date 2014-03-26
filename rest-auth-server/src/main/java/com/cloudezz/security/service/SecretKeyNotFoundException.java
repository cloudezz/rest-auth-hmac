package com.cloudezz.security.service;

public class SecretKeyNotFoundException extends RuntimeException {

  private static final long serialVersionUID = -8377239220332757198L;

  public SecretKeyNotFoundException(String message) {
    super(message);
  }


  public SecretKeyNotFoundException(String message, Throwable cause) {
    super(message, cause);
  }


  public SecretKeyNotFoundException(Throwable cause) {
    super(cause);
  }

}
