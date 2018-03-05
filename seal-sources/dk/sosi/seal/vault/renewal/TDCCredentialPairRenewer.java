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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/TDCCredentialPairRenewer.java $
 * $Id: TDCCredentialPairRenewer.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal;

import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.pki.DistinguishedName;
import dk.sosi.seal.ssl.HttpsConnector;
import dk.sosi.seal.ssl.HttpsConnectorImpl;
import dk.sosi.seal.ssl.TrustedServerCertificateIssuers;
import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.renewal.model.*;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtilException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Renewal of CredentialPair implementation.
 * 
 * Both renewal of TDC test certificates (issued under the cn=TDC Systemtest CA II root) and TDC production certificates
 * is supported.
 * 
 * Please note, that renewal of TDC production certificates is a chargeable service.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class TDCCredentialPairRenewer extends CredentialPairRenewer { // NOPMD

	private static final String TEST_URL = "https://test.udstedelse.certifikat.tdc.dk:443/flexws/flexws";
	private static final String PROD_URL = "https://udstedelse.certifikat.tdc.dk:443/flexws/flexws";

	private HttpsConnector connector;

	private URL serviceURL;

	public TDCCredentialPairRenewer(Properties properties) {
		super();
		this.properties = properties;
	}


	/**
	 * @see dk.sosi.seal.vault.renewal.CredentialPairRenewer#renew(dk.sosi.seal.vault.CredentialPair)
	 */
	public CredentialPair renew(CredentialPair pair) throws RenewalException {

		try {
			if (connector == null) {
				connector = new HttpsConnectorImpl(pair, TrustedServerCertificateIssuers.getTrustedServerCertificateIssuers());
			}
			serviceURL = new URL(selectURL(pair.getCertificate()));

			String reply = post(RenewalFactory.serializeRequest(new RequestRenewalRequest()));
			RenewalAuthorization auth = RenewalFactory.deserializeRequestRenewalResponse(properties, reply);
			assertStatusOK(auth.getStatusCode(), auth.getStatusText());

			KeyGenerator kg = new KeyGenerator(auth.getReferenceNumber(), properties);
			kg.generateKeyPair();

			RenewCertificateRequest req = new RenewCertificateRequest(
					auth.getReferenceNumber(), 
					auth.getRenewalAuthorizationCode(),
					kg.getCertificateRequest()
			);

			reply = post(RenewalFactory.serializeRequest(req));
			IssueResult result = RenewalFactory.deserializeRenewCertificateResponse(properties, reply);
			assertStatusOK(result.getStatusCode(), result.getStatusText());

            CredentialPair renewedPair = new CredentialPair(
                    CertificateParser.asCertificate(result.getIssuedUserCertificate()),
					kg.getPrivateKey()
			);
			return renewedPair;
		} catch (MalformedURLException e) {
			throw new RenewalException("Failed to renew credentials", e);
		} catch (IOException e) {
			throw new RenewalException("Failed to renew credentials", e);
		} catch (XmlUtilException e) {
			throw new RenewalException("Failed to renew credentials", e);
		} catch (ModelBuildException e) {
			throw new RenewalException("Failed to renew credentials", e);
		}

	}
	
	
	/**
	 * @see dk.sosi.seal.vault.renewal.CredentialPairRenewer#isRenewalChargeable(java.security.cert.X509Certificate)
	 */
	public boolean isRenewalChargeable(X509Certificate certificate) {
		DistinguishedName dn = new DistinguishedName(certificate.getIssuerDN().getName());
		
		return dn.getCountry().equals("DK") && dn.getOrganization().equals("TDC") && dn.getCommonName().equals("TDC OCES CA"); 
	}





	private String selectURL(X509Certificate certificate) {
		if (isTDCTestCertificate(certificate)) {
			return TEST_URL; // NOPMD
		} else {
			return PROD_URL;
		}
	}

	private boolean isTDCTestCertificate(X509Certificate certificate) {
		return certificate.getIssuerDN().getName().indexOf("TDC OCES Systemtest CA II") != -1;
	}
	
	

	private void assertStatusOK(int statusCode, String statusText) throws RenewalException {
		if (statusCode != 0) {
			throw new RenewalException("Failed to renew credentials: "	+ statusText);
		}
	}

	private String post(String message) throws IOException {
		return connector.postSOAP(message, serviceURL);
	}

	public HttpsConnector getConnector() {
		return connector;
	}

	public void setConnector(HttpsConnector connector) {
		this.connector = connector;
	}

}
