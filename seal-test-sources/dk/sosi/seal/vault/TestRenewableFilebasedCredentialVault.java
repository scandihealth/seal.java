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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/vault/TestRenewableFilebasedCredentialVault.java $
 * $Id: TestRenewableFilebasedCredentialVault.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */

package dk.sosi.seal.vault;

import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.vault.renewal.MockCredentialPairRenewer;
import junit.framework.TestCase;

import java.io.File;
import java.util.Properties;

public class TestRenewableFilebasedCredentialVault extends TestCase {

	public static final File KEYSTORE_FILE = TestFileBasedCredentialVault.KEYSTORE_FILE;
	public static final String KEYSTORE_PASSWORD = TestFileBasedCredentialVault.KEYSTORE_PASSWORD;

	public static RenewableFileBasedCredentialVault getCredentialVault() throws CredentialVaultException {

		RenewableFileBasedCredentialVault credentialVault;
		if (KEYSTORE_FILE.exists()) {
			if(!KEYSTORE_FILE.delete()) fail("Failed to delete existing keystore file");
		}
		credentialVault = new RenewableFileBasedCredentialVault(SignatureUtil.setupCryptoProviderForJVM(), KEYSTORE_FILE, KEYSTORE_PASSWORD);
		return credentialVault;
	}
	
	public void testRenew() {
		RenewableFileBasedCredentialVault vault = getCredentialVault();
		try {
			vault.renewSystemCredentials();
			fail("renew without system credentials should result in a credential vault exception");
		} catch (CredentialVaultException e) {
			//OK
		}

		CredentialVault voces = CredentialVaultTestUtil.getVocesCredentialVault();
		vault.setSystemCredentialPair(voces.getSystemCredentialPair());
		vault.setCredentialPairRenewer(new MockCredentialPairRenewer());
		
		vault.renewSystemCredentials();
		
		assertNotNull(vault.getArchivedSystemCredentialPair(1));
		assertNull(vault.getArchivedSystemCredentialPair(2));
		
		//Test persistence of changes
		
		Properties properties = SignatureUtil.setupCryptoProviderForJVM();
		RenewableFileBasedCredentialVault readVault = new RenewableFileBasedCredentialVault(properties, KEYSTORE_FILE, KEYSTORE_PASSWORD);
		assertNotNull(readVault.getArchivedSystemCredentialPair(1));
		assertNull(readVault.getArchivedSystemCredentialPair(2));
		
		//Exhaust renewals
		
		readVault.setCredentialPairRenewer(new MockCredentialPairRenewer());
		
		for(int i = 0; i < 12; i++) {
			readVault.renewSystemCredentials();
		}
		readVault = new RenewableFileBasedCredentialVault(properties, KEYSTORE_FILE, KEYSTORE_PASSWORD);
		assertNotNull(readVault.getArchivedSystemCredentialPair(1));
		assertNotNull(readVault.getArchivedSystemCredentialPair(2));
		assertNotNull(readVault.getArchivedSystemCredentialPair(9));
		assertNotNull(readVault.getArchivedSystemCredentialPair(10));
		assertNull(readVault.getArchivedSystemCredentialPair(11));
		
		assertEquals(readVault.getSystemCredentialPair().getPrivateKey(), readVault.getArchivedSystemCredentialPair(10).getPrivateKey());
	}


}
