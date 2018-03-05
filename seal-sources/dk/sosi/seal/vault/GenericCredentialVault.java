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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/GenericCredentialVault.java $
 * $Id: GenericCredentialVault.java 11216 2013-09-05 10:02:21Z ChristianGasser $
 */
package dk.sosi.seal.vault;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.pki.AuditEventHandler;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;

/**
 * CredentialVault implementation, which stores the internal KeyStore in memory.
 *
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class GenericCredentialVault implements PropertyConfiguredCredentialVault {

	protected KeyStore keyStore;
	protected String keyStorePassword;

	protected Properties properties;

	private void log(){
		SOSIFactory.getAuditEventHandler(properties).onInformationalAuditingEvent(
				AuditEventHandler.EVENT_TYPE_INFO_CREDENTIAL_VAULT_INITIALIZED,
				new Object[]{this}
				);
	}

	public GenericCredentialVault(Properties properties, KeyStore keyStore, String keyStorePassword) throws CredentialVaultException {
		this.properties = properties;
		if (keyStore == null) {
			throw new CredentialVaultException("Keystore cannot be null!");
		}
		this.keyStore = keyStore;

		if (keyStorePassword == null) {
			throw new CredentialVaultException("Keystore password cannot be null!");
		}
		this.keyStorePassword = keyStorePassword;

		log();
	}

	/**
	 * Create a generic credential vault based off a JKS java keystore in memory
	 *
	 * @throws CredentialVaultException
	 *             If the keystore could not be created
	 */
	protected GenericCredentialVault(Properties properties) throws CredentialVaultException {
		this.properties = properties;
		try {
			keyStore = KeyStore.getInstance("JKS");
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Unable to create Java Keystore", e);
		}
	}

	/**
	 * Create an in-memory credential vault, secured by the supplied password
	 *
	 * @param keyStorePassword
	 *            Credential to access vault
	 * @throws CredentialVaultException
	 *             If the underlying keystore had issues.
	 */
	public GenericCredentialVault(Properties properties, String keyStorePassword) throws CredentialVaultException {
		this(properties);
		setKeyStorePassword(keyStorePassword);
		try {
			keyStore.load(null, keyStorePassword.toCharArray());
		} catch (IOException e) {
			throw new CredentialVaultException("Unable to create Java Keystore", e);
		} catch (NoSuchAlgorithmException e) {
			throw new CredentialVaultException("Unable to create Java Keystore", e);
		} catch (CertificateException e) {
			throw new CredentialVaultException("Unable to create Java Keystore", e);
		}
		log();
	}

	public boolean isTrustedCertificate(X509Certificate certificate) throws CredentialVaultException {
		try {
			return keyStore.getCertificateAlias(certificate) != null;
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Unable to query underlying keystore", e);
		}
	}

	/**
	 * @return The current system credential pair (certificate + private key) or
	 *         <code>null</code> if none has been associated with this
	 *         credential vault.
	 */
	public CredentialPair getSystemCredentialPair() throws CredentialVaultException {
		return getCredentialPairByAlias(ALIAS_SYSTEM);
	}

	protected CredentialPair getCredentialPairByAlias(String alias) throws CredentialVaultException {
		try {
			if (!keyStore.isKeyEntry(alias))
				return null; // NOPMD
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Unable to query underlying keystore", e);
		}

		try {
			return new CredentialPair(
					(X509Certificate) keyStore.getCertificate(alias),
					(PrivateKey) keyStore.getKey(alias, keyStorePassword.toCharArray())
			);
		} catch (NoSuchAlgorithmException e) {
			throw new CredentialVaultException("Problem accessing system certificate", e);
		} catch (UnrecoverableKeyException e) {
			throw new CredentialVaultException("Problem accessing system certificate", e);
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Problem accessing system certificate", e);
		}

	}

	/**
	 * Install the system certificate + private key pair
	 *
	 * @param credentialPair
	 *            Certificate and corresponding private key
	 * @throws CredentialVaultException
	 *             If an internal keystore error occurs
	 */
	public void setSystemCredentialPair(CredentialPair credentialPair) throws CredentialVaultException {
		setCredentialPairByAlias(credentialPair, ALIAS_SYSTEM);
	}

	protected void setCredentialPairByAlias(CredentialPair credentialPair, String alias) throws CredentialVaultException {
		try {
			keyStore.setKeyEntry(alias, credentialPair.getPrivateKey(), keyStorePassword.toCharArray(), new Certificate[] { credentialPair.getCertificate() });
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Unable to install System certificate", e);
		}
	}

	/**
	 * Install the system certificate + private key pair from a pkcs12 file
	 *
	 * @param pkcs12file
	 *            Certificate and corresponding private key
	 * @param password
	 *            Used to unlock the private key
	 * @throws CredentialVaultException
	 *             If an internal keystore error occurs
	 */
	public void setSystemCredentialPair(InputStream pkcs12file, String password) throws CredentialVaultException {
		CredentialPair systemCredentialPair = loadKeyPairFromPKCS12(pkcs12file, password);
		setSystemCredentialPair(systemCredentialPair);
	}

	/**
	 * Add the supplied certificate under the supplied alias
	 *
	 * @param certificate
	 *            The certificate to add
	 * @param alias
	 *            The alias under which to add the certificate
	 * @throws CredentialVaultException
	 *             If an internal keystore error occurs
	 */
	public void addTrustedCertificate(X509Certificate certificate, String alias) throws CredentialVaultException {
		try {
			keyStore.setCertificateEntry(alias, certificate);
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Unable to install trusted certificate", e);
		}
	}

	/**
	 * Remove the certificate specified by alias
	 *
	 * @param alias
	 * @throws CredentialVaultException
	 *             If alias is not a certificate, does not exist or an internal
	 *             keystore error occurs
	 */
	public void removeTrustedCertificate(String alias) throws CredentialVaultException {
		try {
			if (!keyStore.isCertificateEntry(alias)) {
				throw new CredentialVaultException("The supplied alias '" + alias + "' is not a certificate entry");
			}
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Internal error accessing keystore", e);
		}

		try {
			keyStore.deleteEntry(alias);
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Unable to install certificate", e);
		}
	}

	/**
	 * Get the trusted certificate specified by the alias
	 *
	 * @param alias
	 *            Alias that points to certificate
	 * @return X509Certificate
	 * @throws CredentialVaultException
	 *             If no such certificate exists or an internal error occured.
	 */
	public X509Certificate getTrustedCertificate(String alias) throws CredentialVaultException {
		try {
			return (X509Certificate) keyStore.getCertificate(alias);
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Unable to access certificate under alias '" + alias + "'");
		}
	}

	/**
	 * @return the underlying keystore
	 */
	public KeyStore getKeyStore() {

		return keyStore;
	}

	/**
	 * Import system certificate and private key from a PKCS12 keystore.
	 *
	 * @param pkcs12file
	 *            The PKCS12 (.pfx, .p12) file to import
	 * @param password
	 *            Password to access PKCS12 file
	 * @throws CredentialVaultException
	 *             If import failed.
	 */
	public void setSystemCredentialPair(File pkcs12file, String password) throws CredentialVaultException {

		CredentialPair systemCredentialPair = loadKeyPairFromPKCS12(pkcs12file, password);
		setSystemCredentialPair(systemCredentialPair);
	}

	/**
	 * Adds a trusted certificate based on an Alias and a X509 encoded file.
	 *
	 * @param x509file
	 * @param alias
	 * @throws CredentialVaultException
	 */
	public void addTrustedCertificate(File x509file, String alias) throws CredentialVaultException {

		X509Certificate certificate = (X509Certificate) loadCertificateFromX509(x509file);
		addTrustedCertificate(certificate, alias);
	}

    /**
     * Returns the underlying properties
     */
    public Properties getProperties() {
        return properties;
    }

	/** --- Private parts --- */

	protected void setKeyStorePassword(String keyStorePassword) {

		this.keyStorePassword = keyStorePassword;
	}

	protected CredentialPair loadKeyPairFromPKCS12(InputStream pkcs12instream, String password) throws CredentialVaultException {
		KeyStore pkcs12KeyStore;
		CredentialPair credentialPair = null;

		try {
			String provider = SignatureUtil.getCryptoProvider(properties,SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_PKCS12);
			pkcs12KeyStore = KeyStore.getInstance("PKCS12",provider);

			pkcs12KeyStore.load(pkcs12instream, password.toCharArray());
			pkcs12instream.close();
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Unable to load PKCS12 file " + pkcs12instream, e);
		} catch (IOException e) {
			throw new CredentialVaultException("Unable to load PKCS12 file " + pkcs12instream, e);
		} catch (NoSuchAlgorithmException e) {
			throw new CredentialVaultException("Unable to load PKCS12 file " + pkcs12instream, e);
		} catch (CertificateException e) {
			throw new CredentialVaultException("Unable to load PKCS12 file " + pkcs12instream, e);
		} catch (NoSuchProviderException e) {
			throw new CredentialVaultException("No Such Provider", e);
		}

		// The BouncyCastle provider does not allow for testing the alias type
		// via the isXXX methods
		// of the KeyStore, but uses the same alias for Certificate and
		// PrivateKey when type is PKCS12
		try {
			Enumeration<String> aliases = pkcs12KeyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				if (pkcs12KeyStore.isKeyEntry(alias)) {
					X509Certificate cert = (X509Certificate) pkcs12KeyStore.getCertificate(alias);
					PrivateKey key = (PrivateKey) pkcs12KeyStore.getKey(alias, password.toCharArray());
					credentialPair = new CredentialPair(cert, key);
				}
			}
		} catch (KeyStoreException e) {
			throw new CredentialVaultException("Unable to get private key or certificate from PKCS12 keystore", e);
		} catch (NoSuchAlgorithmException e) {
			throw new CredentialVaultException("Unable to get private key or certificate from PKCS12 keystore", e);
		} catch (UnrecoverableKeyException e) {
			throw new CredentialVaultException("Unable to get private key or certificate from PKCS12 keystore", e);
		}

		return credentialPair;
	}

	/**
	 * Read certificate and private key from a PKCS12 keystore. This method will
	 * expect a keystore with a single certificate and a single private key.
	 * Trusted certificate chains will be ignored.
	 *
	 * @param pkcs12file
	 *            The PKCS12 (.pfx, .p12) file to import
	 * @param password
	 *            Password to access PKCS12 file
	 * @return CredentialPair containing Certificate and Private Key
	 * @throws CredentialVaultException
	 *             If import failed.
	 */
	protected CredentialPair loadKeyPairFromPKCS12(File pkcs12file, String password) throws CredentialVaultException {
		FileInputStream fileInputStream;
		try {
			fileInputStream = new FileInputStream(pkcs12file);
		} catch (FileNotFoundException e) {
			throw new CredentialVaultException("Unable to load pkcs12 keystore from file " + pkcs12file, e);
		}
		return loadKeyPairFromPKCS12(fileInputStream, password);
	}

	/**
	 * Load an x509 certificate from file (DER encoded binary or Base 64)
	 *
	 * @param x509file
	 *            The x509 certificate to load
	 * @return A Java Certificate
	 * @throws CredentialVaultException
	 *             If certificate could not be loaded
	 */
	protected Certificate loadCertificateFromX509(File x509file) throws CredentialVaultException {

		Certificate cert;
		try {
			FileInputStream fileInputStream = new FileInputStream(x509file);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			cert = cf.generateCertificate(fileInputStream);
		} catch (FileNotFoundException e) {
			throw new CredentialVaultException("Unable to load certificate file", e);
		} catch (CertificateException e) {
			throw new CredentialVaultException("Unable to load certificate file", e);
		}
		return cert;
	}
}