package com.cloudezz.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.cloudezz.security.service.SecretKeyService;
import com.cloudezz.security.utils.HMACUtils;

public class RestHMACAuthProvider implements AuthenticationProvider {

  @Autowired
  protected SecretKeyService secretKeyService;

  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    RestHMACAuthToken restToken = (RestHMACAuthToken) authentication;

    // api key (aka username)
    String apiKey = restToken.getPrincipal();
    
    // hashed blob
    RestHMACCredentials credentials = restToken.getCredentials();

    String secret = "";
    // get secret access key from api key
    secret = secretKeyService.getSecretKey(restToken.getPrincipal());

    // if that username does not exist, throw exception
    if (secret == null) {
      throw new BadCredentialsException("Invalid username or apikey.");
    }

    // calculate the hmac of content with secret key
    String hmac = HMACUtils.calculateHMAC(secret, credentials.getRequestData());
    // check if signatures match

   /* if (!credentials.getSignature().equals(hmac)) {
      throw new BadHMACAuthRequestException("Auth Failed : Invalid HMAC signature.");
    }*/

    
    return restToken;
  }

  public boolean supports(Class<?> authentication) {
    return RestHMACAuthToken.class.equals(authentication);
  }
}
