package com.unipoint.security.core;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.unipoint.security.jwt.FirebaseAuthenticationToken;
import com.unipoint.security.util.AuthBuilder;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import com.google.api.client.util.Strings;


public class FirebaseAuthenticationTokenFilter extends AbstractAuthenticationProcessingFilter {

	private final AuthBuilder authBuilder;

	public FirebaseAuthenticationTokenFilter(AuthBuilder authBuilder) {
		super(authBuilder.getAuthPath());
		this.authBuilder = authBuilder;
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		final String authToken = request.getHeader(authBuilder.getTokenHeader());
		if (Strings.isNullOrEmpty(authToken)) {
			throw new AuthenticationServiceException("Invaild auth token");
		}

		return getAuthenticationManager().authenticate(new FirebaseAuthenticationToken(authToken));
	}
	
	/**
     * Make sure the rest of the filterchain is satisfied
     *
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);

        // As this authentication is in HTTP header, after success we need to continue the request normally
        // and return the response as if the resource was not secured at all
        chain.doFilter(request, response);
    }
}