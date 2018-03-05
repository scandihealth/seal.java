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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/TDCCredentialPairIssuer.java $
 * $Id: TDCCredentialPairIssuer.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault;

import dk.sosi.seal.pki.PKIException;
import dk.sosi.seal.ssl.HttpsConnector;
import dk.sosi.seal.ssl.HttpsConnectorImpl;
import dk.sosi.seal.ssl.TrustedServerCertificateIssuers;
import dk.sosi.seal.vault.renewal.KeyGenerator;
import dk.sosi.seal.vault.renewal.model.RenewalException;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Class capable of issuing a certificate from TDC referencenumber and installation-code.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class TDCCredentialPairIssuer { //NOPMD
	private static final String CERTIFICATE_BEGIN = "<certificate>";
	private static final String CERTIFICATE_END = "</certificate>";
	private static final String CERTIFICATE_ERROR_BEGIN = "<certificate error>";
	private static final String CERTIFICATE_ERROR_END = "</certificate error>";
	private static final String CERTIFICATES_BEGIN = "<certificates>";
	private static final String CERTIFICATES_END = "</certificates>";
	private HttpsConnector connector;
	private Properties properties;
	
	public TDCCredentialPairIssuer(Properties properties) {
		this.properties = properties;
	}
	
	/**
	 * Retrieve certificate from TDC.
	 * @param referenceNumber
	 * 		referenceNumber included in TDC email
	 * @param installationCode
	 * 		installationCode included in TDC letter
	 * @param isTest
	 * 		pass <code>true</code> to issue certificate from TDC test environment. 
	 * @return
	 * 		new <code>CredentialPair</code>
	 * @throws PKIException
	 */
	public CredentialPair issue(String referenceNumber, String installationCode, boolean isTest) throws PKIException {
		
		try {
			if (connector == null) {
				connector = new HttpsConnectorImpl(TrustedServerCertificateIssuers.getTrustedServerCertificateIssuers());
			}

			KeyGenerator kg = new KeyGenerator(referenceNumber, properties);
			kg.generateKeyPair();

			String message = buildMessage(referenceNumber, installationCode, kg.getCertificateRequest());
			String result = connector.post(message, getServiceUrl(isTest), getRequestProperties());

			X509Certificate userCert = parse(result);
			
			return new CredentialPair(userCert, kg.getPrivateKey());
			
		} catch (RenewalException e) {
			throw new PKIException("Failed to issue certificate", e);
		} catch (UnsupportedEncodingException e) {
			throw new PKIException("Failed to issue certificate", e);
		} catch (IOException e) {
			throw new PKIException("Failed to issue certificate", e);
		}

	}
	
	public void setHttpsConnector(HttpsConnector connector) {
		this.connector = connector;
	}

	private Map<String, String> getRequestProperties() {
		Map<String, String> props = new HashMap<String, String>();
		props.put("User-Agent", "tdc-opencert");
		return props;
	}

	private String buildMessage(String referenceNumber, String installationCode, byte[] certificateRequest) throws UnsupportedEncodingException {
		StringBuffer message = new StringBuffer();
		message.append("myKey=");
		message.append(URLEncoder.encode(XmlUtil.toBase64(certificateRequest), "UTF-8"));
		message.append("&PIN=");
		message.append(installationCode);
		message.append("&REFNO=");
		message.append(referenceNumber);
		return message.toString();
	}

	private URL getServiceUrl(boolean isTest) throws PKIException {
		try {
			if(isTest) {
				return new URL("https://test.lra.certifikat.tdc.dk/udstedelse/jsp/flexretrieve.jsp"); //NOPMD
			} else {
				return new URL("https://lra.certifikat.tdc.dk/udstedelse/jsp/flexretrieve.jsp");
			}
		} catch (MalformedURLException e) {
			throw new PKIException("Failed to issue certificate", e);
		}
	}
	
    private X509Certificate parse(String responseString) throws PKIException {
        if (responseContainsNoCertificates(responseString)) {
            if (responseContainsErrorMessage(responseString)) {
                throw new PKIException("Failed to issue certificate: " + extractErrorMessage(responseString));
            } else {
            	throw new PKIException("Failed to issue certificate");
            }
        }

        List<String> certs = extractCertificates(responseString);

        //Both the issued user certificate and the root certificate are returned from TDC.
        if(certs.size() != 2) {
            throw new PKIException("Wrong number of certificates in reply from CA");
        }

        //The root certificate is discarded
        return CertificateParser.asCertificate(XmlUtil.fromBase64(certs.get(0)));
    }

	private List<String> extractCertificates(String responseString) {
		List<String> certs = new ArrayList<String>();
        String certificates = extractCertificatesTag(responseString);
        while (certificates.toLowerCase().indexOf(CERTIFICATE_BEGIN) != -1) {
            String certificate = extractCertificate(certificates);
            certs.add(certificate);
            certificates = certificates.substring(certificates.toLowerCase().indexOf(CERTIFICATE_END) + CERTIFICATE_END.length());
        }
		return certs;
	}

	private String extractErrorMessage(String responseString) {
		return extractTagContent(responseString, CERTIFICATE_ERROR_BEGIN, CERTIFICATE_ERROR_END);
	}

	private String extractTagContent(String responseString, String beginTag, String endTag) {
		return responseString.substring(
				responseString.toLowerCase().indexOf(beginTag) + beginTag.length(),
				responseString.toLowerCase().indexOf(endTag)
		).trim();
	}

	private boolean responseContainsErrorMessage(String responseString) {
		return responseString.toLowerCase().indexOf(CERTIFICATE_ERROR_BEGIN) != -1;
	}

	private boolean responseContainsNoCertificates(String responseString) {
		return responseString.toLowerCase().indexOf(CERTIFICATES_BEGIN) == -1;
	}

	private String extractCertificatesTag(String responseString) {
		return extractTagContent(responseString, CERTIFICATES_BEGIN, CERTIFICATES_END);
	}

	private String extractCertificate(String certificates) {
		return extractTagContent(certificates, CERTIFICATE_BEGIN, CERTIFICATE_END);
	}

}
