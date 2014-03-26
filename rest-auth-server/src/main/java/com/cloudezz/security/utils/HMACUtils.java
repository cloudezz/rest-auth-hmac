package com.cloudezz.security.utils;

import java.security.GeneralSecurityException;
import java.text.ParseException;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.time.DateUtils;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.crypto.codec.Base64;

import com.cloudezz.security.AuthenticationRequestWrapper;

public class HMACUtils {

  // Enable Multi-Read for PUT and POST requests
  private static final Set<String> METHOD_HAS_CONTENT = new TreeSet<String>(
      String.CASE_INSENSITIVE_ORDER) {
    private static final long serialVersionUID = 1L;
    {
      add("PUT");
      add("POST");
    }
  };

  public static String calculateHMAC(String secret, String data) {
    try {
      SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(signingKey);
      byte[] rawHmac = mac.doFinal(data.getBytes());
      String result = new String(Base64.encode(rawHmac));
      return result;
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException();
    }
  }

  public static String calculateContentToSign(AuthenticationRequestWrapper request) {

    Md5PasswordEncoder md5 = new Md5PasswordEncoder();

    String salt = "cloud-ezz-salt";
    // get timestamp
    String timestamp = request.getHeader("Date");

    // get md5 content and content-type if the request is POST or PUT method
    boolean hasContent = METHOD_HAS_CONTENT.contains(request.getMethod());
    String contentMd5 = hasContent ? md5.encodePassword(request.getPayload(), salt) : "";
    String contentType = hasContent ? request.getContentType() : "";

    // calculate content to sign
    StringBuilder toSign = new StringBuilder();
    toSign.append(request.getMethod()).append("\n").append(contentMd5).append("\n")
        .append(contentType).append("\n").append(timestamp).append("\n")
        .append(request.getRequestURI());

    return toSign.toString();
  }

  public static Date getTimeStampUTC(AuthenticationRequestWrapper request) {
    // calculate UTC time from timestamp (usually Date header is GMT but still...)
    Date date = null;
    try {
      // get timestamp
      String timestamp = request.getHeader("Date");
      if (timestamp != null)
        date = DateUtils.parseDate(timestamp, new String[] {"yyyy-MM-ddTHH:mm:ss.S"});
    } catch (ParseException ex) {
      ex.printStackTrace();
    }

    return date;
  }



}
