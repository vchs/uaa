package org.cloudfoundry.identity.uaa.authentication.ldap;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.authentication.BindAuthenticator;


/**
 * This extention of the bind authenticator is required to support a multi tenanted
 * user database backed by ldap where the username is scoped by a tenant id. It
 * extends the username by concatenating the tenant id so that the tuple can be consumed
 * by downstream libraries.
 *
 * @author jdsa
 *
 */
public class TenantRecognizingBindAuthenticator extends BindAuthenticator {

	public TenantRecognizingBindAuthenticator(BaseLdapPathContextSource contextSource) {
		super(contextSource);
	}

	@Override
	public DirContextOperations authenticate(Authentication authentication) {

		String tenantId = ((UaaAuthenticationDetails)((UsernamePasswordAuthenticationToken) authentication).getDetails()).getTenantId();
		String principal = (String) authentication.getPrincipal();
		principal = tenantId + "/" + principal;

		UsernamePasswordAuthenticationToken tenantedAuthentication =
				new UsernamePasswordAuthenticationToken(principal, authentication.getCredentials(), authentication.getAuthorities());
		tenantedAuthentication.setAuthenticated(authentication.isAuthenticated());
		tenantedAuthentication.setDetails(authentication.getDetails());

		return super.authenticate(tenantedAuthentication);
	}
}
