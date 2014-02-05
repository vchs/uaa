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

public class LdapUaaUserDatabase implements UaaUserDatabase {

	private LdapTemplate ldapTemplate = null;
	private String[] searchAttributes = {"objectguid","cn","mail","userPrincipalName","gn","sn","memberOf"};

	public LdapUaaUserDatabase(LdapTemplate ldapTemplate) {
		this.ldapTemplate = ldapTemplate;
	}

	@SuppressWarnings("unchecked")
	@Override
	public UaaUser retrieveUserByName(String username) throws UsernameNotFoundException {
		AndFilter filter = new AndFilter();
		filter.and(new EqualsFilter("mail", username));

		List<UaaUser> results = ldapTemplate.search(
			     "", filter.encode(), SearchControls.SUBTREE_SCOPE,
			     searchAttributes,
			     new UaaUserAttributesMapper());

		if (null != results && results.size() > 0) {
			return results.get(0);
		} else {
			throw new UsernameNotFoundException(username);
		}
	}

	public class UaaUserAttributesMapper implements AttributesMapper {
		@Override
		public UaaUser mapFromAttributes(Attributes attrs) throws NamingException {
			String id = getAttributeValue(attrs, "objectguid");
			String username = getAttributeValue(attrs, "cn");
			String email = getAttributeValue(attrs, "mail");
			if (null == email) {
				email = getAttributeValue(attrs, "userPrincipalName");
			}
			String givenName = getAttributeValue(attrs, "gn");
			String familyName = getAttributeValue(attrs, "sn");
			List<String> groups = getAttributeValues(attrs, "memberOf");

			List<GrantedAuthority> authorities =
					AuthorityUtils.commaSeparatedStringToAuthorityList(convertToScopes(groups));

			// TODO: Authorities needs to change to map the users group membership along with the default authorities
			return new UaaUser(id, username, null, email, authorities, givenName, familyName, new Date(),
					new Date());
		}

		private String convertToScopes(List<String> groups) {
			ArrayList<String> scopeList = new ArrayList<String>();

			for (String group : groups) {
				DistinguishedName dn = new DistinguishedName(group);
				//dn.getAll() will return the components in order
				List<String> dnComponents = Collections.list(dn.getAll());

				Iterator<String> i = dnComponents.iterator();

				while(i.hasNext() && !i.next().equals("cn=tenants")) {}

				String dnComponent = i.next();
				String[] attributeNameAndValue = dnComponent.split("=");
				String scope = attributeNameAndValue[1];

				while(i.hasNext()) {
					dnComponent = i.next();
					attributeNameAndValue = dnComponent.split("=");
					scope += "." + attributeNameAndValue[1];
				}

				scopeList.add(scope);
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

		private List getAttributeValues(Attributes attrs, String attributeName) throws NamingException {
			Attribute attribute = attrs.get(attributeName);
			if(null != attribute) {
				return Collections.list(attribute.getAll());
			} else {
				return null;
			}
		}
	}
}
