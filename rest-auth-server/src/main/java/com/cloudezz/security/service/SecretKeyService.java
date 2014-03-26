package com.cloudezz.security.service;

public interface SecretKeyService {

  /**
   * Get the secret key based on the user key like username, email or user api key
   * @param userKey
   * @return
   */
  public String getSecretKey(String userKey) throws SecretKeyNotFoundException;
}
