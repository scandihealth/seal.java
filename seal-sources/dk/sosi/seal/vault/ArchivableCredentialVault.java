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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/ArchivableCredentialVault.java $
 * $Id: ArchivableCredentialVault.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.vault;

import java.security.KeyStore;
import java.util.Properties;

/**
 * <p>
 * Specialization of GenericCredentialVault, that allows the system credentials to 
 * be archived and replaced by a new set of system credentials.
 * </p>
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: chg@lakeside.dk $
 * @version $Revision: 8697 $
 * @since 1.0
 */
public class ArchivableCredentialVault extends GenericCredentialVault {

	private static final int KEY_PAIRS_TO_KEEP = 10;
	
	public ArchivableCredentialVault(Properties properties) throws CredentialVaultException {
		super(properties);
	}

	public ArchivableCredentialVault(Properties properties, String keyStorePassword) throws CredentialVaultException {
		super(properties, keyStorePassword);
	}


	public ArchivableCredentialVault(Properties properties, KeyStore keyStore, String keyStorePassword) throws CredentialVaultException {
		super(properties, keyStore, keyStorePassword);
	}


	/**
	 * Fetch an archived system credential pair 
	 * @param id The id
	 * @return The associated <code>CredentialPair</code>.
	 */
	public CredentialPair getArchivedSystemCredentialPair(int id) {
		String alias = getArchiveEntryAlias(id);
		return getCredentialPairByAlias(alias);
	
	}

	protected void setArchivedSystemCredentialPair(int id, CredentialPair credentialPair) {
		String alias = getArchiveEntryAlias(id);
		setCredentialPairByAlias(credentialPair, alias);
	
	}

	private String getArchiveEntryAlias(int id) {
		String alias = ALIAS_SYSTEM + "_" + id;
		return alias;
	}

	/**
	 * <p>
	 * Replace the current system credentials by the passed credential pair.
	 * Further, archive the current system credentials, allowing them to 
	 * be recovered later.
	 * </p>
	 * @param renewedPair
	 * 		the credential pair that should replace the current system credentials
	 */
	public void archiveSystemCredentials(CredentialPair renewedPair) {
		for (int i = KEY_PAIRS_TO_KEEP - 1; i > 0; i--) {
			CredentialPair temp = getArchivedSystemCredentialPair(i);
			if (temp != null) {
				setArchivedSystemCredentialPair(i + 1, temp);
			}
		}
	
		setArchivedSystemCredentialPair(1, getSystemCredentialPair());
		setSystemCredentialPair(renewedPair);
	}
	
	
	

}
