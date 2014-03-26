package com.cloudezz.security;

import java.util.Date;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;


public class RestHMACAuthToken extends UsernamePasswordAuthenticationToken {

  private static final long serialVersionUID = -9021106139110827313L;
  
  private Date timestamp;

  public RestHMACAuthToken(Object principal, RestHMACCredentials credentials, Date timestamp) {
    super(principal, credentials,AuthorityUtils.NO_AUTHORITIES);
    this.timestamp = timestamp;
  }

  @Override
  public String getPrincipal() {
    return (String) super.getPrincipal();
  }

  @Override
  public RestHMACCredentials getCredentials() {
    return (RestHMACCredentials) super.getCredentials();
  }

  public Date getTimestamp() {
    return timestamp;
  }

}
