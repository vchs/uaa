package org.cloudfoundry.identity.uaa.authentication.manager;

import java.security.SecureRandom;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.password.PasswordEncoder;

public class TenantAwareLdapAuthzAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {

	private ApplicationEventPublisher eventPublisher;
	private final PasswordEncoder encoder = new BCryptPasswordEncoder();
	private final UaaUserDatabase userDatabase;
	private final Log logger = LogFactory.getLog(getClass());
	private AccountLoginPolicy accountLoginPolicy = new PermitAllAccountLoginPolicy();
	private final AuthenticationProvider ldapAuthProvider;

	/**
	 * Dummy user allows the authentication process for non-existent and locked out users to be as close to
	 * that of normal users as possible to avoid differences in timing.
	 */
	private final UaaUser dummyUser;

	public TenantAwareLdapAuthzAuthenticationManager(UaaUserDatabase userDatabase, AuthenticationProvider authProvider) {
		this.userDatabase = userDatabase;
		this.dummyUser = createDummyUser();
		this.ldapAuthProvider = authProvider;
	}

	@Override
	public Authentication authenticate(Authentication req) throws AuthenticationException {
		logger.debug("Processing authentication request for " + req.getName());

		if (req.getCredentials() == null) {
			BadCredentialsException e = new BadCredentialsException("No password supplied");
			publish(new AuthenticationFailureBadCredentialsEvent(req, e));
			throw e;
		}

		String tenantId = ((UaaAuthenticationDetails)((UsernamePasswordAuthenticationToken) req).getDetails()).getTenantId();

		UaaUser user;
		Authentication authResponse;
		try {
			user = userDatabase.retrieveUserByName(tenantId + "/" + req.getName().toLowerCase(Locale.US));
			authResponse = ldapAuthProvider.authenticate(req);
		}
		catch (BadCredentialsException bce) {
			user = dummyUser;
			authResponse = null;
		}
		catch (UsernameNotFoundException e) {
			user = dummyUser;
			authResponse = null;
		}

		if (!accountLoginPolicy.isAllowed(user, authResponse)) {
			logger.warn("Login policy rejected authentication for " + user.getUsername() + ", " + user.getId()
					+ ". Ignoring login request.");
			BadCredentialsException e = new BadCredentialsException("Login policy rejected authentication");
			publish(new AuthenticationFailureLockedEvent(req, e));
			throw e;
		}

		if (user == dummyUser) {
			logger.debug("No user named '" + req.getName() + "' was found");
			publish(new UserNotFoundEvent(req));
		} else {
			Authentication success = new UaaAuthentication(new UaaPrincipal(user),
					user.getAuthorities(), (UaaAuthenticationDetails) req.getDetails());
			publish(new UserAuthenticationSuccessEvent(user, success));

			return success;
		}

		BadCredentialsException e = new BadCredentialsException("Bad credentials");
		publish(new AuthenticationFailureBadCredentialsEvent(req, e));
		throw e;
	}

	private void publish(ApplicationEvent event) {
		if (eventPublisher!=null) {
			eventPublisher.publishEvent(event);
		}
	}

	public void setAccountLoginPolicy(AccountLoginPolicy accountLoginPolicy) {
		this.accountLoginPolicy = accountLoginPolicy;
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

	private UaaUser createDummyUser() {
		// Create random unguessable password
		SecureRandom random = new SecureRandom();
		byte[] passBytes = new byte[16];
		random.nextBytes(passBytes);
		String password = encoder.encode(new String(Hex.encode(passBytes)));
		// Unique ID which isn't in the database
		final String id = UUID.randomUUID().toString();

		return new UaaUser("dummy_user", password, null, "dummy_user", "dummy", "dummy") {
			@Override
			public final String getId() {
				return id;
			}

			@Override
			public final List<? extends GrantedAuthority> getAuthorities() {
				throw new IllegalStateException();
			}
		};
	}
}
