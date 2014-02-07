package org.cloudfoundry.identity.uaa.authentication.ldap;

import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;

/**
 * Extends the LDAP search filter capabilities to allow searching
 * for a user in a tenant. Splits the username field to identify the
 * tenant.
 *
 * Changes the search base according to the tenant id
 *
 * @see TenantAwareBindAuthenticator
 *
 * @author jdsa
 *
 */
public class TenantAwareFilterBasedLdapUserSearch implements LdapUserSearch {

	private String dynamicSearchBase = "";

	private final ContextSource contextSource;

	private final String searchFilter;

	public TenantAwareFilterBasedLdapUserSearch(String searchFilter,
			String dynamicSearchBase, BaseLdapPathContextSource contextSource) {
		this.searchFilter = searchFilter;
		this.dynamicSearchBase = dynamicSearchBase;
		this.contextSource = contextSource;
	}

	@Override
	public DirContextOperations searchForUser(String username) {
		String[] tenantSlashUsername = username.split("/");

		String tenantId = tenantSlashUsername[0];
		String email = tenantSlashUsername[1];

		return new FilterBasedLdapUserSearch("", searchFilter,
				(BaseLdapPathContextSource) contextSource).searchForUser(email);
	}

}
