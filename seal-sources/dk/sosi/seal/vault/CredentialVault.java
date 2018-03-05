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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/CredentialVault.java $
 * $Id: CredentialVault.java 9261 2011-10-27 13:01:41Z ads@lakeside.dk $
 */
package dk.sosi.seal.vault;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * An interface representing a store for system credentials. The vault can store
 * both public certificate and a private key (<coe>CredentialPair</code>)
 * for the system that uses this <code>CredentialVault</code>.
 * 
 * @author kkj
 * @author $LastChangedBy: ads@lakeside.dk $
 * @since 1.0
 */
public interface CredentialVault {

    public static final String ALIAS_SYSTEM = System.getProperty("dk.sosi.seal.vault.CredentialVault#Alias", "SOSI:ALIAS_SYSTEM");
    
	/**
	 * Returns <code>true</code> if the passed certificate is a 
	 * trusted certificate..
	 * </p>
	 * Please note: This mechanism should <b>not</b>be used in federations.
	 * In federative architectures please use @link{dk.sosi.seal.pki.Federation} to check STS certificates etc. 
	 * 
	 * @param certificate
	 *            the certificate to check.
	 * @throws CredentialVaultException
	 *             if anything unexpected happened.
	 */
	boolean isTrustedCertificate(X509Certificate certificate) throws CredentialVaultException;

	/**
	 * Gets the credential pair (private key and certificate) embedded in this
	 * credential vault.
	 * 
	 * @throws CredentialVaultException
	 *             if anything unexpected happened.
	 */
	CredentialPair getSystemCredentialPair() throws CredentialVaultException;

	/**
	 * Associates a credential pair (private key and certificate) to this
	 * credential vault.
	 * 
	 * @param credentialPair
	 *            the credential pair to associate
	 * @throws CredentialVaultException
	 *             if anything unexpected happened.
	 */
	void setSystemCredentialPair(CredentialPair credentialPair) throws CredentialVaultException;

	/**
	 * Returns the underlying keystore.
	 */
	KeyStore getKeyStore();
}
