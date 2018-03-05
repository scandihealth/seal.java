/*
 * The MIT License
 *
 * Original work sponsored and donated by National Board of e-Health (NSI), Denmark (http://www.nsi.dk)
 *
 * Copyright (C) 2011 National Board of e-Health (NSI), Denmark (http://www.nsi.dk)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/ssl/SOSIKeyManager.java $
 * $Id: SOSIKeyManager.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.ssl;

import dk.sosi.seal.pki.DistinguishedName;
import dk.sosi.seal.vault.CredentialPair;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * SOSI implementation of JSSE X509KeyManager. This implementation is backed by a SOSI CredentialPair.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class SOSIKeyManager implements X509KeyManager {
	private CredentialPair credentialPair;

	public SOSIKeyManager(CredentialPair credentialPair) {
		super();
		this.credentialPair = credentialPair;
	}

	public String chooseClientAlias(String[] keyTypes, Principal[] issuers,
			Socket socket) {
		// dumpPrincipals(issuers);

		if (contains(credentialPair.getCertificate().getIssuerDN(), issuers)) {
			return getAlias(credentialPair.getCertificate()); //NOPMD
		}
		return null;
	}

	/*
	 * private void dumpPrincipals(Principal[] issuers) { for (int i = 0; i <
	 * issuers.length; i++) { System.out.println("principal " + (i+1) + ": " +
	 * issuers[i]); }
	 *  }
	 */

	public X509Certificate[] getCertificateChain(String alias) {
		if (getAlias(credentialPair.getCertificate()).equals(alias)) {
			return new X509Certificate[] { credentialPair.getCertificate() }; //NOPMD
		}
		return null;
	}

	public String[] getClientAliases(String keyType, Principal[] issuers) {
		if (contains(credentialPair.getCertificate().getIssuerDN(), issuers)) {
			return new String[] { getAlias(credentialPair.getCertificate()) };  //NOPMD
		}
		return null;
	}

	public PrivateKey getPrivateKey(String alias) {
		if (getAlias(credentialPair.getCertificate()).equals(alias)) {
			return credentialPair.getPrivateKey(); //NOPMD
		}
		return null;
	}

	private boolean contains(Principal candidate, Principal[] issuers) {
		for (int i = 0; i < issuers.length; i++) {
			if (equals(issuers[i], candidate))
				return true;  //NOPMD
		}
		return false;
	}

	public String[] getServerAliases(String arg0, Principal[] arg1) {
		return null;
	}

	public String chooseServerAlias(String arg0, Principal[] arg1, Socket arg2) {
		return null;
	}

	private boolean equals(Principal a, Principal b) {

		DistinguishedName dna = new DistinguishedName(a.getName());
		DistinguishedName dnb = new DistinguishedName(b.getName());
	
		return dna.equals(dnb);
    }

	/**
	 * Return a suitable relatively unique alias for a certificate. Due to
	 * various X500 name parsing issues, we use the serialnumber.
	 * 
	 * @param certificate
	 * @return
	 */
	private String getAlias(X509Certificate certificate) {
		
		return "certSerial=" + certificate.getSerialNumber().toString(16).toLowerCase();

	}

}
