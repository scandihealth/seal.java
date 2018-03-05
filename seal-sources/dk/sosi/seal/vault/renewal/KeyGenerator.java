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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/KeyGenerator.java $
 * $Id: KeyGenerator.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.security.CryptoFacade;
import dk.sosi.seal.vault.renewal.model.RenewalException;

import java.security.*;
import java.util.Properties;

/**
 * <p>An RSA key-pair generator used for renewal of system credentials.</p>
 * 
 * <p>
 * The renewal request returns a reference number and an authorization code that
 * authorizes a subsequent certificate issuance. Possession of private key (POP) is
 * implemented by including the reference number in the signed certificate request.
 * </p>
 * 
 * <p>
 * Requires bouncy-castle.
 * </p>
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class KeyGenerator {
	private static final int DEFAULT_KEY_SIZE = 1024;
	private String referenceNumber;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private SecureRandom secureRandom; //NOPMD
	private int keySize = DEFAULT_KEY_SIZE;
	private Properties properties;

	/**
	 * Construct a key generator. 
	 * @param referenceNumber the refencenumber to include in the certificate request
	 */
	public KeyGenerator(String referenceNumber, Properties properties) {
		super();
		this.referenceNumber = referenceNumber;
		this.properties = properties;
	}
	
	/**
	 * Set the size of the generated keys. Default is 1024.
	 * @param keySize
	 */
	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}
	
	/**
	 * Generate the RSA key pair.
	 */
	public void generateKeyPair() throws RenewalException {
		try {
			if(secureRandom == null) {
				secureRandom = new SecureRandom();
			}
			
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA",
					SignatureUtil.getCryptoProvider(properties,
					SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_RSA));

			keyGen.initialize(keySize, secureRandom);
			KeyPair keypair = keyGen.generateKeyPair();
			publicKey = keypair.getPublic();
			privateKey = keypair.getPrivate();
			
		} catch (NoSuchAlgorithmException e) {
			throw new RenewalException("Failed to generate keypair", e);
		} catch (NoSuchProviderException e) {
			throw new RenewalException("Failed to generate keypair", e);
		}
	}

	/**
	 * Returns the certificate request. Must be called after generateKeyPair.
	 * @return The request as a <code>byte</code> array.
	 */
    @Deprecated
    public byte[] getCertificateRequest() {
		return CryptoFacade.getCertificateRequestHandler(properties).getCertificateRequest(publicKey, privateKey, referenceNumber);
	}
	
	/**
	 * Returns the generated private key. Must be called after generateKeyPair.
	 * @return The generated <code>PrivateKey</code>.
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	
	/**
	 * Returns the generated public key. Must be called after generateKeyPair.
	 * @return The generated <code>PublicKey</code>.
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}
}
