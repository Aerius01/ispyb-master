/*
 * LdapLoginModule
 *  
 * Created on Nov 20, 2004
 *
 * Ricardo LEAL
 * ESRF - European Synchrotron Radiation Facility
 * B.P. 220
 * 38043 Grenoble Cedex - France
 * Phone: 00 33 (0)4 38 88 19 59
 * Fax: 00 33 (0)4 76 88 25 42
 * ricardo.leal@esrf.fr
 * 
 */
package ispyb.server.security;

import java.util.ArrayList;
import java.util.List;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.BindResult;

import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.util.ssl.TrustStoreTrustManager;
import com.unboundid.util.ssl.SSLUtil;
import javax.net.ssl.SSLContext;

import org.apache.log4j.Logger;

/**
 * 
 * @author Alberto Nardella alberto.nardella@maxlab.lu.se
 * @version
 */
public class LdapSearchModule {

	private final Logger LOG = Logger.getLogger(LdapSearchModule.class);
	private	static String principalDNPrefix = "uid=";
	private	static String principalDNSuffix = ",ou=People,dc=psf,dc=bessy,dc=de";
	private	static String groupUniqueMemberName = "uniqueMember";
	private	static String groupAttributeID = "cn";
	private	static String groupCtxDN = "ou=ispyb,ou=Group,dc=psf,dc=bessy,dc=de";
	private	static String server = "vsrv9.exp1401.bessy.de";
	private	static String trustStorePath = "/ispyb-core/dependencies/jdk1.8.0_421/jre/lib/security/cacerts";

	public LdapSearchModule() {

	}
	
	public ArrayList<String> getUserGroups(String username) throws Exception {
		ArrayList<String> myRoles = new ArrayList<String>();
  
		// Create the connection to the LDAP server over the non-secured port 389, and then start the
		// TLS encyrption
		LDAPConnection connection = new LDAPConnection(server, 389);

		SSLUtil sslUtil = new SSLUtil(new TrustStoreTrustManager(trustStorePath));
		SSLContext sslContext = sslUtil.createSSLContext();
		StartTLSExtendedRequest startTLSRequest = new StartTLSExtendedRequest(sslContext);

		ExtendedResult startTLSResult;
		try {
			startTLSResult = connection.processExtendedOperation(startTLSRequest);
		} catch (LDAPException le) {
			startTLSResult = new ExtendedResult(le);
			System.out.println("error: " + le.getMessage());
		}
		
		// Look up all role groups to which the authenticated user pertains
		// The filter is constructed as a series of AND (&) bool conditions from left to right
		Filter filter = Filter.create("(&(objectClass=groupOfUniqueNames)(" + groupAttributeID + "=*)(" + 
			groupUniqueMemberName + "=" + principalDNPrefix + username + ",dc=psf,dc=bessy,dc=de))");

		SearchRequest searchReq = new SearchRequest(groupCtxDN, SearchScope.SUB, filter, groupAttributeID);
		SearchResult searchResult;

		try {
			searchResult = connection.search(searchReq);
			
			for (SearchResultEntry entry : searchResult.getSearchEntries()) {
				// Fill roles array
				String roleName = entry.getAttributeValue("cn");
				System.out.println("Found role: " + roleName);
				if (roleName != null) {
					myRoles.add(roleName);
				}
			}
		} catch (LDAPSearchException lse) {
			searchResult = lse.getSearchResult();
			ResultCode resultCode = lse.getResultCode();
			String errorMessageFromServer = lse.getDiagnosticMessage();

			System.out.println("server message: " + errorMessageFromServer);
		}

		/** Any validated user is in role User **/
		if (myRoles.size() == 0){
			myRoles.add("User");
		}

		connection.close();

		return myRoles;
	}
}
