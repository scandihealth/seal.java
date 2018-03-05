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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/MainTester.java $
 * $Id: MainTester.java 20887 2015-01-15 10:20:38Z ChristianGasser $
 */
package dk.sosi.seal;

import dk.sosi.seal.model.*;
import dk.sosi.seal.pki.*;
import dk.sosi.seal.pki.impl.intermediate.TestIntermediateCertificateStoreAdapter;
import dk.sosi.seal.ssl.TestHttpsConnector;
import dk.sosi.seal.ssl.TestSOSIKeyManager;
import dk.sosi.seal.ssl.TestSOSITrustManager;
import dk.sosi.seal.ssl.TestTrustedServerCertificateIssuers;
import dk.sosi.seal.tool.TestSeal;
import dk.sosi.seal.vault.*;
import dk.sosi.seal.vault.renewal.TestCredentialPairIssuer;
import dk.sosi.seal.vault.renewal.TestCredentialPairRenewer;
import dk.sosi.seal.vault.renewal.TestKeyGenerator;
import dk.sosi.seal.vault.renewal.TestRenewalModel;
import dk.sosi.seal.xml.TestAxisUtil;
import dk.sosi.seal.xml.TestDebugErrorHandler;
import dk.sosi.seal.xml.TestXmlUtil;
import junit.framework.TestSuite;

import java.security.Provider;
import java.security.Security;
import java.util.Properties;

public class MainTester {

    public static TestSuite suite() {
		Properties properties = SignatureUtil.setupCryptoProviderForJVM();

		TestSuite suite = new TestSuite();
		suite.addTestSuite(TestJVM.class);
		suite.addTestSuite(TestSOSIFactory.class);
		suite.addTestSuite(TestModel.class);
		suite.addTestSuite(TestMessages.class);
		suite.addTestSuite(TestSignatureUtil.class);
		suite.addTestSuite(TestSOSIKeyManager.class);
		suite.addTestSuite(TestSOSITrustManager.class);
		suite.addTestSuite(TestHttpsConnector.class);
		suite.addTestSuite(TestSeal.class);
		suite.addTestSuite(TestClasspathCredentialVault.class);
		suite.addTestSuite(TestFileBasedCredentialVault.class);
		suite.addTestSuite(TestGenericCredentialVault.class);
		suite.addTestSuite(TestRenewableFilebasedCredentialVault.class);
		suite.addTestSuite(TestCredentialPairRenewer.class);
		if(isBCOnClasspath(properties)) {
			suite.addTestSuite(TestKeyGenerator.class);
			suite.addTestSuite(TestCredentialPairIssuer.class);
		} else
			System.out.println("TestKeyGenerator,TestPKI,TestCredentialPairIssuer disabled because of BC dependency");
		suite.addTestSuite(TestRenewalModel.class);
		suite.addTestSuite(TestXmlUtil.class);
		suite.addTestSuite(TestTrustCache.class);
		suite.addTestSuite(TestXMLFormatting.class);
		suite.addTestSuite(TestDGWSVersions.class);
		suite.addTestSuite(TestAuthenticationLevel2.class);
        suite.addTestSuite(TestCertificationAuthorityFactory.class);
        suite.addTestSuite(TestCommonsLoggingAuditEventHandler.class);
        suite.addTestSuite(TestTrustedServerCertificateIssuers.class);
        suite.addTestSuite(TestAxisUtil.class);
        suite.addTestSuite(TestDebugErrorHandler.class);
        suite.addTestSuite(TestFederation.class);
        suite.addTestSuite(TestAbstractOCESCertificationAuthority.class);
        suite.addTestSuite(TestInMemoryCRLCache.class);
        suite.addTestSuite(TestOCESCertificateResolver.class);
        suite.addTestSuite(TestIntermediateCertificateStoreAdapter.class);

		return suite;
	}

	/**
	 * Runs the test suite using the textual runner.
	 */
	public static void main(String[] args) {

		junit.textui.TestRunner.run(suite());
	}

    public static boolean isBCOnClasspath(Properties properties) {
        String property = properties.getProperty(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOFACADE_CERTIFICATE_REQUEST_HANDLER);
        if(property == null || SOSIFactory.PROPERTYVALUE_SOSI_CRYPTOFACADE_BC_CERTIFICATE_REQUEST_HANDLER.equals(property)) {
            try {
                Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance();
                return true;
            } catch (InstantiationException e) {
            } catch (IllegalAccessException e) {
            } catch (ClassNotFoundException e) {
            }
        }
        return false;
    }

    public static boolean addBCAsProvider() throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        if(Security.getProvider(SOSIFactory.PROPERTYVALUE_SOSI_CRYPTOPROVIDER_BOUNCYCASTLE) == null) {
            Security.addProvider((Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance());
            return true;
        }
        return false;
    }

    public static void removeBCAsProvider() {
        Security.removeProvider(SOSIFactory.PROPERTYVALUE_SOSI_CRYPTOPROVIDER_BOUNCYCASTLE);
    }
}
