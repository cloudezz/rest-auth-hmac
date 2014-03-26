package com.cloudezz.security;

public class RestHMACCredentials {

  private String requestData;
  private String signature;

  public RestHMACCredentials(String requestData, String signature) {
    this.requestData = requestData;
    this.signature = signature;
  }

  public String getRequestData() {
    return requestData;
  }

  public String getSignature() {
    return signature;
  }
}
