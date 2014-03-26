package com.cloudezz.security;

import org.springframework.security.core.AuthenticationException;

public class BadHMACAuthRequestException extends AuthenticationException {

  private static final long serialVersionUID = -7077831616235440174L;


  /**
   * Constructs a <code>BadHMACAuthRequestException</code> with the specified message.
   * 
   * @param msg the detail message
   */
  public BadHMACAuthRequestException(String msg) {
    super(msg);
  }


  /**
   * Constructs a <code>BadHMACAuthRequestException</code> with the specified message and root
   * cause.
   * 
   */
  public BadHMACAuthRequestException(String msg, Throwable t) {
    super(msg, t);
  }
}
