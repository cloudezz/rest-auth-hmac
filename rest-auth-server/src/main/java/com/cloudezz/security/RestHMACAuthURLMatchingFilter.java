package com.cloudezz.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;

import com.cloudezz.security.utils.HMACUtils;

public class RestHMACAuthURLMatchingFilter extends AbstractAuthenticationProcessingFilter {

  protected RegexRequestMatcher urlRegex;

  protected boolean continueChainBeforeSuccessfulAuthentication = false;

  public RestHMACAuthURLMatchingFilter(String defaultFilterProcessesUrl) {
    super(defaultFilterProcessesUrl);
  }

  public RestHMACAuthURLMatchingFilter(RegexRequestMatcher urlRegex) {
    super(urlRegex);
    this.urlRegex = urlRegex;
    setAllowSessionCreation(false);
  }



  @Override
  public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse resp)
      throws AuthenticationException, IOException, ServletException {

    AuthenticationRequestWrapper request =
        new AuthenticationRequestWrapper((HttpServletRequest) req);

    // Get authorization header
    String signature = request.getHeader("Authorization");

    String principal = request.getHeader("apiKey");

    // a rest credential is composed by request data to sign and the signature
    RestHMACCredentials restCredential =
        new RestHMACCredentials(HMACUtils.calculateContentToSign(request), signature);

    // Create an authentication token
    RestHMACAuthToken authentication =
        new RestHMACAuthToken(principal, restCredential, HMACUtils.getTimeStampUTC(request));

    // Allow subclasses to set the "details" property
    setDetails(request, authentication);

    return authentication;

  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {

    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;

    if (!requiresAuthentication(request, response)) {
      chain.doFilter(request, response);

      return;
    }

    if (logger.isDebugEnabled()) {
      logger.debug("Request is to process authentication");
    }

    Authentication authResult;

    try {
      authResult = attemptAuthentication(request, response);
      if (authResult == null) {
        unsuccessfulAuthentication(request, response, new BadHMACAuthRequestException(
            "Authentication attempt failed !"));
      }
    } catch (InternalAuthenticationServiceException failed) {
      logger.error("An internal error occurred while trying to authenticate the user.", failed);
      unsuccessfulAuthentication(request, response, failed);

      return;
    } catch (AuthenticationException failed) {
      // Authentication failed
      unsuccessfulAuthentication(request, response, failed);

      return;
    }

    // Authentication success
    if (continueChainBeforeSuccessfulAuthentication) {
      chain.doFilter(request, response);
    }

    successfulAuthentication(request, response, chain, authResult);
  }

  /**
   * Provided so that subclasses may configure what is put into the authentication request's details
   * property.
   * 
   * @param request that an authentication request is being created for
   * @param authRequest the authentication request object that should have its details set
   */
  protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
    authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
  }


  /**
   * Because we require the client to send credentials with every request, we must authenticate on
   * every request
   */
  @Override
  protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
    return urlRegex.matches(request);
  }

  /**
   * Indicates if the filter chain should be continued prior to delegation to
   * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, Authentication)},
   * which may be useful in certain environment (such as Tapestry applications). Defaults to
   * <code>false</code>.
   */
  public void setContinueChainBeforeSuccessfulAuthentication(
      boolean continueChainBeforeSuccessfulAuthentication) {
    this.continueChainBeforeSuccessfulAuthentication = continueChainBeforeSuccessfulAuthentication;
  }

}
