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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/RenewableFileBasedCredentialVault.java $
 * $Id: RenewableFileBasedCredentialVault.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */
package dk.sosi.seal.vault;

import dk.sosi.seal.vault.renewal.CredentialPairRenewer;

import java.io.File;
import java.util.Properties;

/**
 * An extension of the file based credential vault, allowing the vaulted system certificate and
 * private key to be renewed.
 * The old credentials are archived in the key store.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class RenewableFileBasedCredentialVault extends FileBasedCredentialVault {
	private CredentialPairRenewer renewer;

	public RenewableFileBasedCredentialVault(Properties properties, File keyStoreFile, String keyStorePassword) {
		super(properties, keyStoreFile, keyStorePassword);

		if(getSystemCredentialPair() != null) {
			renewer = CredentialPairRenewer.createInstance(getSystemCredentialPair().getCertificate(),properties);
		}
	}

	private void assertWritePermission() {
		if (!keyStoreFile.canWrite()) {
			throw new CredentialVaultException("Keystore file is not writable");
		}
	}


	/**
	 * Renew the system credentials. A new keypair is generated, and the TDC renewal webservice
	 * is used to issue a new certificate.
	 */
	public void renewSystemCredentials() {
		assertWritePermission();
		if(getSystemCredentialPair() == null) { 
			throw new CredentialVaultException("No system credentials to renew");
		}
		
		if(renewer == null) {
			renewer = CredentialPairRenewer.createInstance(getSystemCredentialPair().getCertificate(), properties);
		}
		CredentialPair renewedPair = renewer.renew(getSystemCredentialPair());

		archiveSystemCredentials(renewedPair);
		saveKeyStore();
	}

	
	public void setCredentialPairRenewer(CredentialPairRenewer renewer) {
		this.renewer = renewer;
	}

	public boolean isRenewalChargeable() {
		return this.renewer.isRenewalChargeable(this.getSystemCredentialPair().getCertificate());
	}

}
