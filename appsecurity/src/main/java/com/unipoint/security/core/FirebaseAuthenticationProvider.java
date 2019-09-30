package com.unipoint.security.core;

import java.util.concurrent.ExecutionException;

import com.unipoint.security.jwt.FirebaseAuthenticationToken;
import com.unipoint.security.jwt.FirebaseUserDetails;
import com.unipoint.security.util.AuthBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;

import com.google.api.core.ApiFuture;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;

@Component
public class FirebaseAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

	private final AuthBuilder authBuilder;
	@Autowired
	private FirebaseAuth firebaseAuth;

	public FirebaseAuthenticationProvider(AuthBuilder authBuilder) {
		this.authBuilder = authBuilder;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return (FirebaseAuthenticationToken.class.isAssignableFrom(authentication));
	}

	@Override
	protected void additionalAuthenticationChecks(UserDetails userDetails,
												  UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
	}

	@Override
	protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		final FirebaseAuthenticationToken authenticationToken = (FirebaseAuthenticationToken) authentication;

		ApiFuture<FirebaseToken> task = firebaseAuth.verifyIdTokenAsync(authenticationToken.getToken());
		try {
			FirebaseToken token = task.get();
			return new FirebaseUserDetails(token.getEmail(), token.getUid());
		} catch (InterruptedException | ExecutionException e) {
			throw new SessionAuthenticationException(e.getMessage());
		}
	}
}