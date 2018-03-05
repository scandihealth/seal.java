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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/ssl/SOSITrustManager.java $
 * $Id: SOSITrustManager.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.ssl;

import javax.net.ssl.X509TrustManager;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * SOSI implementation of JSSE X509TrustManager. Handles ordered chains in arbitrary direction. 
 * Handles termination of chains by root certificate or termination by chain certificate just above the root.
 * </p>
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class SOSITrustManager implements X509TrustManager {

	private List<X509Certificate> trustedCertificates;

	public SOSITrustManager() {
		super();
		trustedCertificates = new ArrayList<X509Certificate>();
	}

	/**
	 * 
	 * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[],
	 *      java.lang.String)
	 */
	public void checkClientTrusted(X509Certificate[] chain, String authType) {
	}


	/**
	 * 
	 * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[],
	 *      java.lang.String)
	 */
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		
		if (!isChainValid(chain)) {
			throw new CertificateException("Presented chain is not valid.");
		}

		if (!isTrustedCertificate(getTerminatingCertificate(chain))) {
			throw new CertificateException("Presented chain is not trusted");
		}

	}
	
	
	/**
	 * 
	 * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
	 */
	public X509Certificate[] getAcceptedIssuers() {
		return trustedCertificates.toArray(new X509Certificate[0]);
	}
	
	/**
	 * Adds a CA certificate to be trusted by the trust manager.
	 * @param trusted
	 */
	public void addTrustedCertificate(X509Certificate trusted) {
		trustedCertificates.add(trusted);
	}

	
	private boolean isChainValid(X509Certificate[] chain) throws CertificateException {
		//Chains of length 1 are trivially valid
		if (chain.length == 1) {
			return true; // NOPMD
		}

		boolean issuerFirst = isIssuerFirstOrdering(chain);
		for (int i = 0; i < chain.length - 1; i++) {
			chain[i].checkValidity();
			
			X509Certificate issuer;
			X509Certificate subject;

			if (issuerFirst) {
				issuer = chain[i];
				subject = chain[i + 1];
			} else {
				issuer = chain[i + 1];
				subject = chain[i];
			}

			if (!isIssuerSubjectPair(issuer, subject)) {
				return false;   // NOPMD
			}

		}

		return true;
	}


	private boolean isIssuerFirstOrdering(X509Certificate[] chain) {
		if(chain.length == 1) return true; //NOPMD
		return chain[0].getSubjectX500Principal().equals(chain[1].getIssuerX500Principal());
	}

	private boolean isIssuerSubjectPair(X509Certificate issuer, X509Certificate subject) throws CertificateException {
		try {
			subject.verify(issuer.getPublicKey());
			return true; //NOPMD
		} catch (InvalidKeyException e) {
			//Thrown when signature verification fails for BouncyCastle, caught...
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException(e);
		} catch (SignatureException e) { //NOPMD
			//Thrown when signature verification fails, caught...
		}
		return false;

	}

	private X509Certificate getTerminatingCertificate(X509Certificate[] chain) {
		if (isIssuerFirstOrdering(chain)) {
			return chain[0];  //NOPMD
		}
		return chain[chain.length - 1];
	}

	private boolean isTrustedCertificate(X509Certificate candidate) throws CertificateException {

		boolean isCACert = isCACertificate(candidate);
		for (Iterator<X509Certificate> iter = trustedCertificates.iterator(); iter.hasNext();) {
			X509Certificate trusted = iter.next();
			if (isCACert) {
				//The candidate certificate must be in the trusted list
				try {
					if (Arrays.equals(trusted.getEncoded(), candidate.getEncoded())) {
						return true;  // NOPMD
					}
				} catch (CertificateEncodingException e) {
					return false;  // NOPMD
				}
			} else {
				//The candidate must be issued under a root in the trusted list
				if (isIssuerSubjectPair(trusted, candidate)) {
					return true; // NOPMD
				}
			}
		}

		return false;
	}

	private boolean isCACertificate(X509Certificate candidate) {
		return candidate.getIssuerX500Principal().equals(candidate.getSubjectX500Principal());
	}

}
