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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/tool/Seal.java $
 * $Id: Seal.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.tool;

import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.ssl.HttpsConnector;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.renewal.CredentialPairRenewer;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;


/**
 * SOSI Seal command line tool for importing certificates and private keys into
 * a keystore, stored inside a .jar file. This .jar file can subsequently be
 * used to supply the Seal library with the cryptographic elements needed for
 * signing, validation, etc. via a CredentialVault.
 * 
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class Seal { // NOPMD

	private static final String CMD_IMPORTCERT = "-importcert";
	private static final String CMD_IMPORTPKCS12 = "-importpkcs12";
	private static final String CMD_LIST = "-list";
	private static final String CMD_REMOVEALIAS = "-removealias";
    @Deprecated
    private static final String CMD_RENEW = "-renew";
    @Deprecated
    private static final String CMD_ISSUE = "-issue";

	private static final String PARAM_VAULT = "-vault";
	private static final String PARAM_ALIAS = "-alias";
	private static final String PARAM_VAULTPWD = "-vaultpwd";
	private static final String PARAM_PKCS12PWD = "-pkcs12pwd";
	
	private static final String PARAM_KEYSTORE = "-keystore";
	private static final String PARAM_KEYSTOREPWD = "-keystorepwd";
	
	private static final String PARAM_REFERENCENUMBER = "-referencenumber";
	private static final String PARAM_INSTALLATION_CODE = "-installationcode";
	private static final String PARAM_TEST = "-test";
	private static final String PARAM_PROPS = "-props";
	

	private static SealCommands sealCommands;
	
	private static CredentialPairRenewer credentialPairRenewer = null;
	private static HttpsConnector httpsConnector = null;

	private static Properties properties = SignatureUtil.setupCryptoProviderForJVM();

	/**
	 * Arguments:
	 * 
	 * <pre>
	 *  
	 *  -importcert .pkcs12|.cer 
	 *  -alias alias 
	 *  -vault vault.jar 
	 *  -vaultpwd password 
	 *  -importpkcs12 .pkcs12|.cer 
	 *  -alias alias 
	 *  -vault vault.jar 
	 *  -vaultpwd password 
	 *  -pkcs12pwd password
	 *  -removealias 
	 *  -alias alias 
	 *  -vault vault.jar
	 *  -vaultpwd password 
	 *  -list
	 *  -vault vault.jar 
	 *  -vaultpwd password
	 *  -renew
	 *  -keystore keystore.jks
	 *  -keystorepwd password
	 *  -renew
	 *  -vault vault.jar 
	 *  -vaultpwd password
	 *  -issue
	 *  -referencenumber refno
	 *  -installationcode instcode
	 *  -vault vault.jar
	 *  -vaultpwd password
	 *  [-test]
	 * </pre>
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		if (args.length == 0) {
			error("No arguments supplied");
		}

		String cmd = args[0];

		Map<String, String> argMap = new HashMap<String, String>();
		int i = 0;
		while (i < args.length) {
			String key = args[i++];
			String value = null;
			if (CMD_LIST.equals(key) || CMD_RENEW.equals(key) || CMD_REMOVEALIAS.equals(key) || CMD_ISSUE.equals(key) || PARAM_TEST.equals(key)) {
				value = "";
			} else {
				if (i < args.length) {
					value = args[i++];
				}
			}
			argMap.put(key, value);
		}

		if(argMap.containsKey(PARAM_PROPS)) {
			try {
				properties.load(new FileInputStream(argMap.get(PARAM_PROPS)));
			} catch (Exception e) {
				error(e);
			}
		}
		sealCommands = new SealCommands(properties);

		try {
			if (CMD_IMPORTCERT.equals(cmd)) {
				importCert(argMap);
			} else if (CMD_REMOVEALIAS.equals(cmd)) {
				removeAlias(argMap);
			} else if (CMD_IMPORTPKCS12.equals(cmd)) {
				importPkcs12(argMap);
			} else if (CMD_LIST.equals(cmd)) {
				list(argMap);
			} else if (CMD_RENEW.equals(cmd)) {
				renew(argMap);
			} else if (CMD_ISSUE.equals(cmd)) {
				issue(argMap);
			} else {
				error("Unknown command " + cmd);
			}
		} catch (SealToolException e) {
			error(e);
		}
	}

    @Deprecated
    public static void setCredentialPairRenewer(CredentialPairRenewer renewer) {
		credentialPairRenewer = renewer;
	}

    @Deprecated
	public static void setHttpsConnector(HttpsConnector httpsConnector) {
		Seal.httpsConnector = httpsConnector;
	}

	private static void importPkcs12(Map<String, String> argMap) {

		File pkcs12Path = new File(argMap.get(CMD_IMPORTPKCS12));
		File vaultPath = new File(argMap.get(PARAM_VAULT));
		String keystorePassword = argMap.get(PARAM_VAULTPWD);
		String pkcs12Password = argMap.get(PARAM_PKCS12PWD);

		if (!pkcs12Path.exists()) {
			error("The specified pkcs12 file " + pkcs12Path.getAbsolutePath() + " does not exist");
		}

		if (keystorePassword == null || keystorePassword.length() == 0) {
			error("No password for the keystore supplied");
		}

		sealCommands.importPkcs12Keystore(vaultPath, keystorePassword, pkcs12Path, pkcs12Password);
	}

	private static void list(Map<String, String> argMap) {

		if(!(argMap.containsKey(PARAM_VAULT) || argMap.containsKey(PARAM_KEYSTORE))) {
 			error("You must specify a vault- or a keystore file name");
		}
		
		if(!argMap.containsKey(PARAM_VAULT)) {
			String keystore = argMap.get(PARAM_KEYSTORE);
			
			if(!argMap.containsKey(PARAM_KEYSTOREPWD)) {
				error("You must specify a keystore password");
			}
			String keystorePassword = argMap.get(PARAM_KEYSTOREPWD);
			sealCommands.list(keystore, keystorePassword);
			
		} else {
			File vaultPath = new File(argMap.get(PARAM_VAULT));
			String keystorePassword = argMap.get(PARAM_VAULTPWD);
			if (keystorePassword == null || keystorePassword.length() == 0) {
				error("No password for the keystore supplied");
			}

			if (!vaultPath.exists()) {
				error("The specified credentialvault jar file " + vaultPath + " does not exit");
			}

			sealCommands.list(vaultPath, keystorePassword);
		}
	}

	private static void removeAlias(Map<String, String> argMap) {

		File vaultPath = new File(argMap.get(PARAM_VAULT));
		String alias = argMap.get(PARAM_ALIAS);
		String keystorePassword = argMap.get(PARAM_VAULTPWD);

		if (!vaultPath.exists()) {
			error("The specified credential vault .jar file " + vaultPath.getAbsolutePath() + " does not exit");
		}

		if (alias == null || alias.length() == 0) {
			error("No alias for the certificate supplied");
		}

		if (keystorePassword == null || keystorePassword.length() == 0) {
			error("No password for the keystore supplied");
		}

		sealCommands.removeAlias(vaultPath, keystorePassword, alias);
	}

	private static void importCert(Map<String, String> argMap) {

		File certPath = new File(argMap.get(CMD_IMPORTCERT));
		File vaultPath = new File(argMap.get(PARAM_VAULT));
		String alias = argMap.get(PARAM_ALIAS);
		String keystorePassword = argMap.get(PARAM_VAULTPWD);

		if (!certPath.exists()) {
			error("The specified certificate file " + certPath.getAbsolutePath() + " does not exit");
		}

		if (alias == null || alias.length() == 0) {
			error("No alias for the certificate supplied");
		}

		if (CredentialVault.ALIAS_SYSTEM.equals(alias)) {
			error("The alias '" + CredentialVault.ALIAS_SYSTEM + "' is reserved for Seal internal usage!");
		}

		if (keystorePassword == null || keystorePassword.length() == 0) {
			error("No password for the keystore supplied");
		}

		sealCommands.importCertificate(vaultPath, certPath, keystorePassword, alias, true);
	}

    @Deprecated
    private static void renew(Map<String, String> argMap) {

		if(credentialPairRenewer != null)
			sealCommands.setCredentialPairRenewer(credentialPairRenewer);

		if(!(argMap.containsKey(PARAM_VAULT) || argMap.containsKey(PARAM_KEYSTORE))) {
 			error("You must specify a vault- or a keystore file name");
		}
		
		if(!argMap.containsKey(PARAM_VAULT)) {
			File keystore = new File(argMap.get(PARAM_KEYSTORE));
			if (!keystore.exists()) {
				error("The specified keystore file " + keystore.getAbsolutePath() + " does not exit");
			}
			
			if(!argMap.containsKey(PARAM_KEYSTOREPWD)) {
				error("You must specify a keystore password");
			}
			String keystorePassword = argMap.get(PARAM_KEYSTOREPWD);

			if (keystorePassword == null || keystorePassword.length() == 0) {
				error("No password for the keystore supplied");
			}
			sealCommands.renewSystemCredentials(keystore, keystorePassword);
			
		} else {
			File vault = new File(argMap.get(PARAM_VAULT));

			if (!vault.exists()) {
				error("The specified vault file " + vault.getAbsolutePath() + " does not exit");
			}
			
			if(!argMap.containsKey(PARAM_VAULTPWD)) {
				error("You must specify a vault password");
			}
			String vaultPassword = argMap.get(PARAM_VAULTPWD);

			if (vaultPassword == null || vaultPassword.length() == 0) {
				error("No password for the keystore supplied");
			}

			sealCommands.renewVaultedSystemCredentials(vault, vaultPassword);
		}

	}

    @Deprecated
    private static void issue(Map<String, String> argMap) {

		if(httpsConnector != null)
			sealCommands.setHttpsConnector(httpsConnector);

		if(!argMap.containsKey(PARAM_VAULT)) {
 			error("You must specify a vault- or a keystore file name");
		}
		
		File vault = new File(argMap.get(PARAM_VAULT));

		if(!argMap.containsKey(PARAM_VAULTPWD)) {
			error("You must specify a vault password");
		}
		String vaultPassword = argMap.get(PARAM_VAULTPWD);

		if (vaultPassword == null || vaultPassword.length() == 0) {
			error("No password for the keystore supplied");
		}
		
		String referenceNumber = argMap.get(PARAM_REFERENCENUMBER);
		if(referenceNumber == null) {
			error("No reference number supplied");
		}
		String installationCode = argMap.get(PARAM_INSTALLATION_CODE);
		if(installationCode == null) {
			error("No installation code supplied");
		}
		
		boolean issueTestCertificate = argMap.containsKey(PARAM_TEST);

		sealCommands.issueToVault(vault, vaultPassword, referenceNumber, installationCode, issueTestCertificate);

	}

	private static void error(Exception e) {
		String message = e.getMessage();
		if (e.getCause() != null) {
			message = message + " (" + e.getCause().getMessage() + ")";
		}
	}

	private static void error(String errorText) {

		System.err.println("Error: " + errorText + "\n");
		System.err.println("Usage: -importcert  <path to .cer> -alias <alias> -vault <vault.jar> -vaultpwd <password> [-props <seal.properties>]");
		System.err.println("       -importpkcs12 <path to .pkcs12> -vault <vault.jar> -vaultpwd <password> -pkcs12pwd <password> [-props <seal.properties>]");
		System.err.println("       -removealias -alias <alias> -vault <vault.jar> -vaultpwd <password> [-props <seal.properties>]");
		System.err.println("       -list -vault <vault.jar> -vaultpwd <password> [-props <seal.properties>]" );
		System.err.println("       -list -keystore <keystore.jks> -keystorepwd <password> [-props <seal.properties>]");
		System.err.println("       -renew -vault <vault.jar> -vaultpwd <password> [-props <seal.properties>]");
		System.err.println("       -renew -keystore <keystore.jks> -keystorepwd <password> [-props <seal.properties>]");
		System.err.println("       -issue -referencenumber <refno> -installationcode <instcode> -vault <vault.jar> -vaultpwd <password> [-test] [-props <seal.properties>]\n");
		System.exit(1);
	}
}
