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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/FileBasedCredentialVault.java $
 * $Id: FileBasedCredentialVault.java 9868 2012-03-20 15:38:18Z chg@lakeside.dk $
 */
package dk.sosi.seal.vault;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Storage for certificates and keys. Backed by a java.security.KeyStore on
 * disk. Exposes SOSI specific methods for handling IdP, System, and trusted
 * certificates. Caveat: Supports only 1 IdP and 1 System certificate at this
 * time, but N trusted certificates.
 * 
 * @author kkj
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public class FileBasedCredentialVault extends ArchivableCredentialVault {

	protected File keyStoreFile;

	/**
	 * Construct a new FileBasedCredentialVault on the supplied keystore file
	 * and protect it with the supplied password. The FileBasedCredentialVault
	 * will be created if none exists, and loaded otherwise. If the method
	 * succeeds, a Java Keystore File with the specifed name is guaranteed to
	 * exist.
	 * 
	 * @param keyStoreFile
	 *            The JKS Java KeyStore File on which this CredentalVault will
	 *            work.
	 * @param keyStorePassword
	 *            The password of the Java KeyStore
	 * @throws CredentialVaultException
	 *             If an operation on the KeyStore failed.
	 */
	public FileBasedCredentialVault(Properties properties, File keyStoreFile, String keyStorePassword) throws CredentialVaultException {

		super(properties);
		setKeyStorePassword(keyStorePassword);
		this.keyStoreFile = keyStoreFile;
		try {
			if (keyStoreFile.exists()) {
				FileInputStream is = new FileInputStream(keyStoreFile);
				keyStore.load(is, keyStorePassword.toCharArray());
				is.close();
			} else {
				keyStore.load(null, keyStorePassword.toCharArray());
                saveKeyStore();
			}
		} catch (IOException e) {
			throw new CredentialVaultException("Unable to load KeyStore file", e);
		} catch (NoSuchAlgorithmException e) {
			throw new CredentialVaultException("Unable to load KeyStore file", e);
		} catch (CertificateException e) {
			throw new CredentialVaultException("Unable to load KeyStore file", e);
		}
	}

	public void setSystemCredentialPair(CredentialPair credentialPair) throws CredentialVaultException {

		super.setSystemCredentialPair(credentialPair);
		saveKeyStore();
	}

	public void addTrustedCertificate(X509Certificate certificate, String alias) throws CredentialVaultException {

		super.addTrustedCertificate(certificate, alias);
		saveKeyStore();
	}

	public void removeTrustedCertificate(String alias) throws CredentialVaultException {

		super.removeTrustedCertificate(alias);
		saveKeyStore();
	}

	// --- Private parts ------

	/**
	 * Flush the in-memory KeyStore to disk
	 * 
	 * @throws CredentialVaultException
	 *             If there was a problem saving the keyStore
	 */
	protected void saveKeyStore() throws CredentialVaultException {

		try {
			FileOutputStream os = new FileOutputStream(keyStoreFile);
			keyStore.store(os, keyStorePassword.toCharArray());
			os.close();
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Unable to save back vault file", e);
		} catch (IOException e) {
			throw new CredentialVaultException("Unable to save back vault file", e);
		} catch (NoSuchAlgorithmException e) {
			throw new CredentialVaultException("Unable to save back vault file", e);
		} catch (CertificateException e) {
			throw new CredentialVaultException("Unable to save back vault file", e);
		}
	}

}
