package com.cloudezz.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.cloudezz.security.service.SecretKeyService;

@Service
public class ClientHMACAuthService {

  @Autowired
  private SecretKeyService secretKeyService;
  

}
