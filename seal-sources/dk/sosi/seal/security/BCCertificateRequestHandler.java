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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/security/BCCertificateRequestHandler.java $
 * $Id: BCCertificateRequestHandler.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */
package dk.sosi.seal.security;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

/**
 * Bouncy Castle specifik implementation of CertificateRequestHandler
 * 
 * @author ${user}
 * @author $$LastChangedBy: ChristianGasser $$
 * @version $$Revision: 20818 $$
 * @since 1.4.2
 */
@Deprecated
public class BCCertificateRequestHandler implements CertificateRequestHandler { //NOPMD

	public byte[] getCertificateRequest(PublicKey publicKey, PrivateKey privateKey, String referenceNumber) {
		//Remove BC again - we will not add BC as provider unwanted.
		boolean bcAdded = false;
		if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
			bcAdded = true;
		}
		
		try {
			PKCS10CertificationRequest pkcs10;
			pkcs10 = new PKCS10CertificationRequest(
					"SHA1WithRSA", new X509Name("CN=" + referenceNumber), publicKey, null, privateKey
			);
			return pkcs10.getEncoded();
		} catch (InvalidKeyException e) {
			throw new CryptoFacadeException("Failed to generate keypair", e);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoFacadeException("Failed to generate keypair", e);
		} catch (NoSuchProviderException e) {
			throw new CryptoFacadeException("Failed to generate keypair", e);
		} catch (SignatureException e) {
			throw new CryptoFacadeException("Failed to generate keypair", e);
		} finally {
			if(bcAdded) {
				Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
			}
		}
	}
}
