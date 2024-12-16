package ispyb.ws.rest.security.login;

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

/**
The authentication in this module uses the unboundid LDAP library instead of the JNDI library. The JNDI
library is what all other synchrotrons are using, but is insufficient for HZB's needs given that our
LDAP functions using the StartTLS method.

StartTLS: This method first connects to the LDAP server over the unsecured port 389. Once the connection is bridged,
the connection is then encrypted using a StartTLSRequest. This is closely related to, but differs from LDAPS (note
the "S" for secure), which connects over port 636. The key difference here is that StartTLS open an insecure connection
and then later secures it, whereas LDAPS opens a secure connection immediately. StartTLS is generally preferred
because then only a single port need be maintained.

JNDI: The library was insufficient for our needs because while it was possible to TLS-secure a connection to port
389 after an anonymous connection (exactly as per the StartTLS method), it was impossible to authenticate any users
thereafter. The dilemma presented itself as follows:

1) HZB's LDAP requires authentication of users over a StartTLS connection
2) User authentication using the JNDI library is only possible when bridging a new connection to the
LDAP server (when creating a new LdapContext instance, supplying host, port, username and password)
3) New JNDI LdapContext instances are only encrypted if connecting over port 636
4) Despite the **many** explicit examples of extended operations using the JNDI library (such as StartTLSRequest)
user credentials would be ignored

It was therefore impossible to authenticate a user using the JNDI system since we needed a secure connection over port 389,
but the only way to authenticate a user is by instantiating a new LdapContext which is always unsecured when connecting
over port 389.
**/

import ispyb.common.util.Constants;

public class HZBLoginModule {
	  /** David James: These values are hardcoded here because ispyb-ws is a separate module from ispyb-ejb, and therefore
	  I don't think they can be sourced from the ispyb-ejb pom.xml file using the ispyb.site-hzb profile, and neither do
	  I think this module can reach the Constants.java file. I have not investigated this claim very deeply though. I ran
	  a simple import of ispyb.common.util.Constants as is the case with:
	  /ispyb-core/ispyb-master/ispyb-ws/src/main/java/ispyb/ws/rest/proposal/DewarRestWebService.java, however when I print
	  the values they are all null for some reason. Not a priority so leaving it for now.

	  private       static String server = Constants.LDAP_Server;
          private       static String principalDNPrefix = Constants.LDAP_Principal_DN_Prefix;
          private       static String principalDNSuffix = Constants.LDAP_Principal_DN_Suffix;
          private       static String groupUniqueMemberName = Constants.LDAP_GroupUniqueMemberName;
          private       static String groupAttributeID = Constants.LDAP_GroupAttributeID;
          private       static String groupCtxDN = Constants.LDAP_GroupCtxDN; **/

	  private	static String server = "vsrv9.exp1401.bessy.de";
	  private	static String principalDNPrefix = "uid=";
	  private	static String principalDNSuffix = ",ou=People,dc=psf,dc=bessy,dc=de";
	  private	static String groupUniqueMemberName = "uniqueMember";
	  private	static String groupAttributeID = "cn";
	  private	static String groupCtxDN = "ou=ispyb,ou=Group,dc=psf,dc=bessy,dc=de";

	  // Note that this is the standard java trust store path .../{java-version}/jre/lib/security/cacerts"
	  private	static String trustStorePath = "/ispyb-core/dependencies/jdk1.8.0_421/jre/lib/security/cacerts";

	public static List<String> authenticate(String username, String password)
			throws Exception {

		List<String> myRoles = new ArrayList<String>();

		if (!password.isEmpty()){
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
			
			// Attempt to bind using the web-form user credentials and only proceed if successful
			BindResult bindResult = connection.bind(principalDNPrefix + username + principalDNSuffix, password);
			System.out.println("LDAP authentication " + bindResult.getResultString());

			if (bindResult.getResultCode().intValue() == 0) {
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
			}

			connection.close();
		}
		else{
			throw new Exception("Empty passwords are not allowed");
		}

		return myRoles;
	}
}
