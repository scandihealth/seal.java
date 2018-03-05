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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/tool/SealCommands.java $
 * $Id: SealCommands.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */
package dk.sosi.seal.tool;

import dk.sosi.seal.ssl.HttpsConnector;
import dk.sosi.seal.vault.*;
import dk.sosi.seal.vault.renewal.CredentialPairRenewer;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;
import java.util.jar.*;


/**
 * The core operations of the Seal tool. This is where the actual grunt work is
 * done, importing certificates, handling .jar content, etc.
 * 
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class SealCommands { // NOPMD
	private static final String KEYSTORE_FILENAME = "SealKeystore.jks";

	private CredentialPairRenewer credentialPairRenewer;
	private HttpsConnector httpsConnector;
	private Properties properties;
	
	public SealCommands(Properties properties) {
		this.properties = properties;
	}

	/**
	 * Import the supplied certificate (.cer) into keystore inside .jar file.
	 * 
	 * @param vaultPath
	 *            The path to the vault.jar file into which certificate will be
	 *            imported
	 * @param certPath
	 *            The path to the certificate file to import
	 * @param keystorePassword
	 *            The password to the embedded keystore
	 * @param alias
	 *            The alias under which to store the certificate
	 * @param createVault
	 *            If true, a new vault will be created if vaultPath does not
	 *            exist
	 */
	public void importCertificate(File vaultPath, File certPath, String keystorePassword, String alias, boolean createVault) throws SealToolException {

		if (!vaultPath.exists()) {
			if (createVault) {
				System.out.println("The supplied vault file " + vaultPath + " does not exist. Attempts to create it");
				initKeystore(vaultPath, keystorePassword);
			} else {
				throw new SealToolException("The supplied vault file " + vaultPath + " does not exist.");
			}
		}

		KeyStore keyStore = getKeyStore(vaultPath, keystorePassword);
		GenericCredentialVault genericCredentialVault = new GenericCredentialVault(properties, keyStore, keystorePassword);
		genericCredentialVault.addTrustedCertificate(certPath, alias);
		saveKeystore(keyStore, vaultPath, keystorePassword);
	}

	/**
	 * Import pkcs12 keystore pcks12Path secured by pkcs12Password into the
	 * vault.jar specified by vaultPath and secured by keystorePassword
	 * 
	 * @param vaultPath
	 *            The full path to the vault.jar
	 * @param keystorePassword
	 *            The password that protects the keystore inside vaultPath
	 * @param pkcs12Path
	 *            The full path to the pkcs12 keystore
	 * @param pkcs12Password
	 *            The password to the pkcs12 keystore
	 */
	public void importPkcs12Keystore(File vaultPath, String keystorePassword, File pkcs12Path, String pkcs12Password) {

		if (!vaultPath.exists()) {
			System.out.println("The supplied vault file " + vaultPath + " does not exist. Attempts to create it");
			initKeystore(vaultPath, keystorePassword);
		}

		KeyStore keyStore = getKeyStore(vaultPath, keystorePassword);
		GenericCredentialVault genericCredentialVault = new GenericCredentialVault(properties, keyStore, keystorePassword);
		genericCredentialVault.setSystemCredentialPair(pkcs12Path, pkcs12Password);
		saveKeystore(keyStore, vaultPath, keystorePassword);
	}

	/**
	 * Issue a set of credentials based on TDC installation code and reference number, and store certificate and
	 * private key into vault.path
	 * 
	 * @param vaultPath
	 *            The full path to the vault.jar
	 * @param keystorePassword
	 *            The password that protects the keystore inside vaultPath
	 * @param referenceNumber
	 * 			  The referencenumber from TDC
	 * @param installationCode
	 * 			  The installationCode from TDC
	 * @param issueTestCertificates
	 * 			  Pass <code>true</code> to issue a TDC test certificate. 
	 *            Pass <code>false</code> to issue a production certificate.
     * @deprecated
     *            Works only for OCES1 certificates, will be removed from Seal when OCES1 reaches end-of-life
	 */
	@Deprecated
    public void issueToVault(File vaultPath, String keystorePassword, String referenceNumber, String installationCode, boolean issueTestCertificates) {
		if (!vaultPath.exists()) {
			System.out.println("The supplied vault file " + vaultPath + " does not exist. Attempts to create it");
			initKeystore(vaultPath, keystorePassword);
		}
		KeyStore keyStore = getKeyStore(vaultPath, keystorePassword);
		GenericCredentialVault genericCredentialVault = new GenericCredentialVault(properties, keyStore, keystorePassword);

		TDCCredentialPairIssuer issuer = new TDCCredentialPairIssuer(properties);
		if(this.httpsConnector != null) {
			issuer.setHttpsConnector(httpsConnector);
		}
		CredentialPair pair = issuer.issue(referenceNumber, installationCode, issueTestCertificates);

		genericCredentialVault.setSystemCredentialPair(pair);
		saveKeystore(keyStore, vaultPath, keystorePassword);
	}
	
	/**
	 * Remove the alias from the vault in vaultPath.
	 * 
	 * @param vaultPath
	 *            The full path to the vault.jar
	 * @param keystorePassword
	 *            The password that protects the vault
	 * @param alias
	 *            The alias to remove
	 * @throws SealToolException
	 *             If the alias does not exist or vault could not be loaded
	 */
	public void removeAlias(File vaultPath, String keystorePassword, String alias) throws SealToolException {

		if (!vaultPath.exists()) {
			System.out.println("The supplied vault file " + vaultPath + " does not exist. Attempts to create it");
			initKeystore(vaultPath, keystorePassword);
		}
		KeyStore keyStore = getKeyStore(vaultPath, keystorePassword);
		try {
			if (!keyStore.containsAlias(alias)) {
				throw new SealToolException("No such alias in keystore '" + alias + "'");
			}
			keyStore.deleteEntry(alias);
		} catch (KeyStoreException e) {
			throw new SealToolException("Unable to delete alias " + alias, e);
		}
		saveKeystore(keyStore, vaultPath, keystorePassword);
	}

	/**
	 * List the content of the vault in vaultPath secured by password
	 * 
	 * @param vaultPath
	 *            The full path to the vault.jar
	 * @param password
	 *            The password that protects the keystore inside
	 * @throws SealToolException
	 *             If listing content failed.
	 */
	public void list(File vaultPath, String password) throws SealToolException {
		KeyStore keyStore = getKeyStore(vaultPath, password);
		list(keyStore);
	}

	/**
	 * List the content of the keystore in keyStorePath secured by password
	 * @param keyStorePath
	 * 		  	The full path to the keystore.jks
	 * @param password
	 *          The password that protects the keystore inside
	 * @throws SealToolException
	 *          If listing content failed.
	 */
	public void list(String keyStorePath, String password) throws SealToolException {
		KeyStore keyStore = getKeyStore(keyStorePath, password);
		list(keyStore);
	}

	
	@Deprecated
    public void setCredentialPairRenewer(CredentialPairRenewer renewer) {
		this.credentialPairRenewer = renewer;
	}
	
	@Deprecated
    public void setHttpsConnector(HttpsConnector httpsConnector) {
		this.httpsConnector = httpsConnector;
	}

	/**
	 * Renew the system credentials stored in a Java keystore.
	 * 
	 * @param keyStoreFile
	 * 				Full path to the Java keystore.
	 * @param keyStorePassword
	 * 				Password protecting the keystore and private keys
     * @deprecated
     *            Works only for OCES1 certificates, will be removed from Seal when OCES1 reaches end-of-life
	 */
	@Deprecated
    public void renewSystemCredentials(File keyStoreFile, String keyStorePassword) throws SealToolException {
		RenewableFileBasedCredentialVault vault = new RenewableFileBasedCredentialVault(properties, keyStoreFile, keyStorePassword);
		if(this.credentialPairRenewer != null) {
			vault.setCredentialPairRenewer(credentialPairRenewer);
		}
		
		if(!vault.isRenewalChargeable() || userAcceptsChargeableRenewal()) {
			vault.renewSystemCredentials();
		}
	}


	/**
	 * Renew the system credentials stored in vault.jar.
	 * 
	 * @param vaultPath
	 *            The full path to the vault.jar
	 * @param password
	 *            The password that protects the keystore inside
     * @deprecated
     *            Works only for OCES1 certificates, will be removed from Seal when OCES1 reaches end-of-life
	 */
	@Deprecated
    public void renewVaultedSystemCredentials(File vaultPath, String password) throws SealToolException {
		
		if (!vaultPath.exists()) {
			throw new SealToolException("The supplied vault file " + vaultPath + " does not exist.");
		}
		KeyStore keyStore = getKeyStore(vaultPath, password);
		ArchivableCredentialVault vault = new ArchivableCredentialVault(properties, keyStore, password);
		
		CredentialPairRenewer renewer = getRenewer(vault.getSystemCredentialPair().getCertificate());

		if(!renewer.isRenewalChargeable(vault.getSystemCredentialPair().getCertificate()) || userAcceptsChargeableRenewal()) {
			CredentialPair renewedPair = renewer.renew(vault.getSystemCredentialPair());
			vault.archiveSystemCredentials(renewedPair);
			keyStore = vault.getKeyStore();
			saveKeystore(keyStore, vaultPath, password);
		}
	}
	
	

	// -- Private parts

	private CredentialPairRenewer getRenewer(X509Certificate certificate) {
		if(this.credentialPairRenewer != null) {
			return this.credentialPairRenewer; //NOPMD
		} else {
			return CredentialPairRenewer.createInstance(certificate, properties);
		}
	}

	private boolean userAcceptsChargeableRenewal() throws SealToolException {
		System.out.println("Renewal of the system certificate will not be free of charge.\n\n" +
				"Do you wish to renew the system certificate? (y/n)");
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		try {
			String line = reader.readLine();
			while(!(line.equals("y") || line.equals("n"))) {
				System.out.println("You must reply by typing either \"y\" or \"n\":");
				line = reader.readLine();
			}
			return line.equals("y");
		} catch (IOException e) {
			throw new SealToolException("Failed to read user input", e);
		}
	}

	
	private void list(KeyStore keyStore) throws SealToolException {

		Enumeration<String> aliases;

		try {
			aliases = keyStore.aliases();
		} catch (KeyStoreException e) {
			throw new SealToolException("Unable to list content of keystore", e);
		}

		System.out.println("Listing contents:\n");

		int count = 1;
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			String type;

			try {
				if (keyStore.isCertificateEntry(alias)) {
					type = "trusted certificate";
				} else if (keyStore.isKeyEntry(alias)) {
					int days = getDaysToExpiry((X509Certificate) keyStore.getCertificate(alias));
					type = "private key, " + days + " days to expiry";
				} else {
					type = "unknown";
				}
			} catch (KeyStoreException e) {
				throw new SealToolException("Unable to read keystore entry " + alias, e);
			}

			System.out.println(count++ + " : " + alias + " (" + type + ")");
		}
	}

	private int getDaysToExpiry(X509Certificate cert) {
		return (int) ((cert.getNotAfter().getTime() - System.currentTimeMillis()) / (24*60*60*1000));
		
	}
	
	private KeyStore getKeyStore(File vaultPath, String password) throws SealToolException {

		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("JKS");
		} catch (KeyStoreException e) {
			throw new SealToolException("Unable to get JKS instance!", e);
		}
		JarInputStream jarInputStream = getJarInputStream(vaultPath);

		try {
			JarEntry jarEntry = jarInputStream.getNextJarEntry();
			while (jarEntry != null) {
				if (KEYSTORE_FILENAME.equals(jarEntry.getName())) {
					try {
						keyStore.load(jarInputStream, password.toCharArray());
					} catch (NoSuchAlgorithmException e) {
						throw new SealToolException("Unable to load keystore from .jar file " + vaultPath, e);
					} catch (CertificateException e) {
						throw new SealToolException("Unable to load keystore from .jar file " + vaultPath, e);
					}
				}
				jarEntry = jarInputStream.getNextJarEntry();
			}
		} catch (IOException e) {
			throw new SealToolException("Unable to read from .jar file " + vaultPath, e);
		} finally {
			try {
				jarInputStream.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return keyStore;
	}

	private KeyStore getKeyStore(String keyStorePath, String password) throws SealToolException {

		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("JKS");
		} catch (KeyStoreException e) {
			throw new SealToolException("Unable to get JKS instance!", e);
		}

		try {
			FileInputStream is = new FileInputStream(new File(keyStorePath));
			keyStore.load(is, password.toCharArray());
			is.close();
		} catch (NoSuchAlgorithmException e) {
			throw new SealToolException("Unable to load keystore from file " + keyStorePath, e);
		} catch (CertificateException e) {
			throw new SealToolException("Unable to load keystore from file " + keyStorePath, e);
		} catch (IOException e) {
			throw new SealToolException("Unable to load keystore from file " + keyStorePath, e);
		}

		return keyStore;
	}

	private JarInputStream getJarInputStream(File vaultPath) throws SealToolException {

		JarInputStream jarInputStream;

		try {
			jarInputStream = new JarInputStream(new FileInputStream(vaultPath));
		} catch (IOException e) {
			throw new SealToolException("Unable to open .jar file " + vaultPath, e);
		}

		return jarInputStream;
	}

	private JarOutputStream getJarOutputStream(File vaultPath) throws SealToolException {

		JarOutputStream jarOutputStream;
		try {
			jarOutputStream = new JarOutputStream(new FileOutputStream(vaultPath));
		} catch (IOException e) {
			throw new SealToolException("Unable to open .jar file " + vaultPath, e);
		}

		return jarOutputStream;
	}

	private void saveKeystore(KeyStore keyStore, File vaultPath, String keystorePassword) {

		JarOutputStream jos = getJarOutputStream(vaultPath);
		JarEntry entry = new JarEntry(ClasspathCredentialVault.KEYSTORE_FILENAME);
		try {
			jos.putNextEntry(entry);
		} catch (IOException e) {
			throw new SealToolException("Unable to add jar entry", e);
		}

		try {
			keyStore.store(jos, keystorePassword.toCharArray());
		} catch (KeyStoreException e) {
			throw new SealToolException("Unable to save keystore back to file", e);
		} catch (IOException e) {
			throw new SealToolException("Unable to save keystore back to file", e);
		} catch (NoSuchAlgorithmException e) {
			throw new SealToolException("Unable to save keystore back to file", e);
		} catch (CertificateException e) {
			throw new SealToolException("Unable to save keystore back to file", e);
		} finally {
			try {
				jos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Initialize an empty keystore, protect it with the supplied password, and
	 * store the result inside the .jar file specified by vaultPath
	 * 
	 * @param vaultPath
	 *            The full path to the vault.jar
	 * @param keystorePassword
	 *            Password to the keystore inside
	 * @throws SealToolException
	 */
	private void initKeystore(File vaultPath, String keystorePassword) throws SealToolException {

		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("JKS");
			keyStore.load(null, keystorePassword.toCharArray());
		} catch (KeyStoreException e) {
			throw new SealToolException("Unable to create empty keystore", e);
		} catch (IOException e) {
			throw new SealToolException("Unable to create empty keystore", e);
		} catch (NoSuchAlgorithmException e) {
			throw new SealToolException("Unable to create empty keystore", e);
		} catch (CertificateException e) {
			throw new SealToolException("Unable to create empty keystore", e);
		}

		JarOutputStream jarOutputStream = null;
		try {
			Manifest manifest = new Manifest();
			Attributes attrCreatedBy = new Attributes();
			attrCreatedBy.putValue("Created-By", "SOSI Seal");
			manifest.getEntries().put("Created-By", attrCreatedBy);

			Attributes attrSpecTitle = new Attributes();
			attrSpecTitle.putValue("Specification-Title", "Seal Certificates");
			manifest.getEntries().put("Specification-Title", attrSpecTitle);

			try {
				jarOutputStream = new JarOutputStream(new FileOutputStream(vaultPath, true), manifest);
			} catch (IOException e) {
				throw new SealToolException("Unable create a jar file for the supplied path " + vaultPath, e);
			}

			JarEntry jarEntry = new JarEntry(ClasspathCredentialVault.KEYSTORE_FILENAME);
			jarEntry.setComment("SOSI Seal Keystore");
			try {
				jarOutputStream.putNextEntry(jarEntry);
			} catch (IOException e) {
				throw new SealToolException("Unable to write keystore to jarfile " + vaultPath, e);
			}
			try {
				keyStore.store(jarOutputStream, keystorePassword.toCharArray());
			} catch (KeyStoreException e) {
				throw new SealToolException("Unable to write keystore to jarfile " + vaultPath, e);
			} catch (IOException e) {
				throw new SealToolException("Unable to write keystore to jarfile " + vaultPath, e);
			} catch (NoSuchAlgorithmException e) {
				throw new SealToolException("Unable to write keystore to jarfile " + vaultPath, e);
			} catch (CertificateException e) {
				throw new SealToolException("Unable to write keystore to jarfile " + vaultPath, e);
			}
		} finally {
			try {
				if (jarOutputStream != null)
					jarOutputStream.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

}
