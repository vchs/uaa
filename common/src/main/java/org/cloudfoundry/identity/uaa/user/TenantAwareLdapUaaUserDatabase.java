package org.cloudfoundry.identity.uaa.user;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;

import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.StringUtils;

public class TenantAwareLdapUaaUserDatabase implements UaaUserDatabase {

	private LdapTemplate ldapTemplate = null;
	private String[] searchAttributes = {"objectguid","cn","mail","userPrincipalName","gn","sn","memberOf"};
	private String userSearchAttribute = null;

	public TenantAwareLdapUaaUserDatabase(LdapTemplate ldapTemplate, String userSearchAttribute) {
		this.ldapTemplate = ldapTemplate;
		this.userSearchAttribute = userSearchAttribute;
	}

	@SuppressWarnings("unchecked")
	@Override
	public UaaUser retrieveUserByName(String username) throws UsernameNotFoundException {

		String[] tenantSlashUsername = username.split("/");

		String tenantId = tenantSlashUsername[0];
		String email = tenantSlashUsername[1];

		AndFilter filter = new AndFilter();
		filter.and(new EqualsFilter(userSearchAttribute, email));

		List<UaaUser> results = ldapTemplate.search(
			     "", filter.encode(), SearchControls.SUBTREE_SCOPE,
			     searchAttributes,
			     new UaaUserAttributesMapper(tenantId));

		if (null != results && results.size() > 0) {
			return results.get(0);
		} else {
			throw new UsernameNotFoundException(username);
		}
	}

	public class UaaUserAttributesMapper implements AttributesMapper {
		private String tenantId = null;

		public UaaUserAttributesMapper(String tenantId) {
			this.tenantId = tenantId;
		}

		@Override
		public UaaUser mapFromAttributes(Attributes attrs) throws NamingException {
			String id = getAttributeValue(attrs, "objectguid");
			String username = getAttributeValue(attrs, "userPrincipalName");
			String email = getAttributeValue(attrs, "userPrincipalName");
			if (null == email) {
				email = getAttributeValue(attrs, "mail");
			}
			String givenName = getAttributeValue(attrs, "gn");
			String familyName = getAttributeValue(attrs, "sn");
			List<String> groups = getAttributeValues(attrs, "memberOf");

			List<GrantedAuthority> authorities =
					AuthorityUtils.commaSeparatedStringToAuthorityList(convertToScopes(tenantId, groups));

			// TODO: Authorities needs to change to map the users group membership along with the default authorities
			return new UaaUser(id, username, null, tenantId, email, authorities, givenName, familyName, new Date(),
					new Date());
		}

		private String convertToScopes(String tenantId, List<String> groups) {
			ArrayList<String> scopeList = new ArrayList<String>();

			for (String group : groups) {
				DistinguishedName dn = new DistinguishedName(group);
				//dn.getAll() will return the components in order
				List<String> dnComponents = Collections.list(dn.getAll());

				Iterator<String> i = dnComponents.iterator();

				//Traverse the base dn till you find ou=tenants
				while(i.hasNext() && !i.next().equals("ou=tenants")) {}

				if (i.hasNext()) {
					//Find the tenant o=coke
					if (i.next().equals("o=" + tenantId)) {
						String dnComponent = i.next();
						String[] attributeNameAndValue = dnComponent.split("=");
						String scope = attributeNameAndValue[1];

						//This is indeed the last dn element (the group that the user belongs to)
						//cn=coke.service.users
						if (!i.hasNext()) {
							scopeList.add(scope);
						}
					}
				}
			}

			String[] scopes = new String[scopeList.size()];
			scopeList.toArray(scopes);

			return StringUtils.arrayToCommaDelimitedString(scopes);
		}

		private String getAttributeValue(Attributes attrs, String attributeName) throws NamingException {
			Attribute attribute = attrs.get(attributeName);
			if(null != attribute) {
				return (String) attribute.get();
			} else {
				return null;
			}
		}

		private List<String> getAttributeValues(Attributes attrs, String attributeName) throws NamingException {
			Attribute attribute = attrs.get(attributeName);
			if(null != attribute) {
				return (List<String>) Collections.list(attribute.getAll());
			} else {
				return null;
			}
		}
	}
}
