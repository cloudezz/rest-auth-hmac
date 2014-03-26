package com.cloudezz.security.service;

public interface SecretKeyService {

  /**
   * Get the secret key based on the user key like username, email or user api key
   * @param userKey
   * @return
   */
  public String getSecretKey(String userKey) throws SecretKeyNotFoundException;
  
  /**
   * In some cases we dont have the userKey so we go with this method
   * @return
   * @throws SecretKeyNotFoundException
   */
  public String getDefaultSecretKey() throws SecretKeyNotFoundException;
  
  
  /**
   * Based on this value we use the default or the user specific key
   * @return
   */
  public boolean useDefault();
}
