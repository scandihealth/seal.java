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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/EmptyCredentialVault.java $
 * $Id: EmptyCredentialVault.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.vault;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class EmptyCredentialVault implements CredentialVault { //NOPMD

	public KeyStore getKeyStore() {
		throw new CredentialVaultException("EmptyVault does not have KeyStore");
	}

	public CredentialPair getSystemCredentialPair() throws CredentialVaultException {
		throw new CredentialVaultException("EmptyVault does not hold SystemCredentialPair");
	}

	public boolean isTrustedCertificate(X509Certificate certificate) throws CredentialVaultException {
		throw new CredentialVaultException("EmptyVault does not have TrustedCertificate");
	}

	public void setSystemCredentialPair(CredentialPair credentialPair) throws CredentialVaultException {
		throw new CredentialVaultException("EmptyVault does not hold SystemCredentialPair");
	}
}