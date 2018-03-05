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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/ClasspathCredentialVault.java $
 * $Id: ClasspathCredentialVault.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.vault;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;


/**
 * Credential vault, which expects "SealKeystore.jks" to be present on the
 * classpath and contain the necessary certificates and private keys. Such a
 * keystore can be created via the dk.sosi.seal.tool.Seal command-line tool,
 * which embeds the keystore inside a jar file for convenience.
 * 
 * @author kkj
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public class ClasspathCredentialVault extends GenericCredentialVault {

	public static final String KEYSTORE_FILENAME = "SealKeystore.jks";
	private static ClassLoader classLoader = null;

	/**
	 * Load the SealKeystore.jks from the classpath
	 * 
	 * @param keyStorePassword
	 *            The password with which the keystore is sealed.
	 * @throws CredentialVaultException
	 *             If keystore could not be loaded
	 */
	public ClasspathCredentialVault(Properties properties, String keyStorePassword) throws CredentialVaultException {
		this(properties, KEYSTORE_FILENAME, keyStorePassword);
	}

	/**
	 * Load a keystore specified by filename from the classpath
	 * 
	 * @param filename
	 * 			The jks file
	 * @param keyStorePassword
	 *            The password with which the keystore is sealed.
	 * @throws CredentialVaultException
	 *             If keystore could not be loaded
	 */
	public ClasspathCredentialVault(Properties properties, String filename, String keyStorePassword) throws CredentialVaultException {
		super(properties);
		setKeyStorePassword(keyStorePassword);

		InputStream is = getResourceAsStream(filename);
		if (is == null) {
			throw new CredentialVaultException("Unable to locate keystore " + filename + " in classpath!");
		}

		try {
			keyStore.load(is, keyStorePassword.toCharArray());
		} catch (IOException e) {
			throw new CredentialVaultException("Unable to load KeyStore file", e);
		} catch (NoSuchAlgorithmException e) {
			throw new CredentialVaultException("Unable to load KeyStore file", e);
		} catch (CertificateException e) {
			throw new CredentialVaultException("Unable to load KeyStore file", e);
		}
	}

	private InputStream getResourceAsStream(String filename) {
		InputStream result;
		if(classLoader == null) {
			result = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename);
		} else {
			result = classLoader.getResourceAsStream(filename);
		}
		return result;
	}

	/**
	 * Set class loader to use when creating instances of <code>ClasspathCredentialVault</code>.
	 * Used for testing purposes only.
	 * 
	 * @param classLoader
	 * 		the implementation of <code>ClassLoader</code> to use.
	 */
	public static void setClassLoader(ClassLoader classLoader) {
		ClasspathCredentialVault.classLoader = classLoader;
	}
	
	public void setSystemCredentialPair(CredentialPair credentialPair) throws CredentialVaultException {
		
		throw new CredentialVaultException("ClasspathCredentialVault is read-only. Please use the seal tool to populate the keystore.");
	}

	public void setSystemCredentialPair(CredentialPair credentialPair, String password) throws CredentialVaultException {
		throw new CredentialVaultException("ClasspathCredentialVault is read-only. Please use the seal tool to populate the keystore.");
	}

	public void setSystemCredentialPair(InputStream pkcs12file, String password) throws CredentialVaultException {

		throw new CredentialVaultException("ClasspathCredentialVault is read-only. Please use the seal tool to populate the keystore.");
	}

	public void addTrustedCertificate(X509Certificate certificate, String alias) throws CredentialVaultException {

		throw new CredentialVaultException("ClasspathCredentialVault is read-only. Please use the seal tool to populate the keystore.");
	}

	public void removeTrustedCertificate(String alias) throws CredentialVaultException {

		throw new CredentialVaultException("ClasspathCredentialVault is read-only. Please use the seal tool to populate the keystore.");
	}

	public void setSystemCredentialPair(File pkcs12file, String password) throws CredentialVaultException {

		throw new CredentialVaultException("ClasspathCredentialVault is read-only. Please use the seal tool to populate the keystore.");
	}

	public void addTrustedCertificate(File x509file, String alias) throws CredentialVaultException {

		throw new CredentialVaultException("ClasspathCredentialVault is read-only. Please use the seal tool to populate the keystore.");
	}
}
