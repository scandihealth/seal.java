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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/test/java/dk/sosi/seal/ssl/MockHttpsConnector.java $
 * $Id: MockHttpsConnector.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */

package dk.sosi.seal.ssl;

import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultException;
import dk.sosi.seal.vault.renewal.model.*;
import dk.sosi.seal.vault.renewal.model.dombuilders.ResponseDOMBuilder;
import dk.sosi.seal.vault.renewal.modelbuilders.RequestModelBuilder;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.util.Map;

public class MockHttpsConnector implements HttpsConnector {
    private CredentialVault vault;
    private String refNo = "12344321";
    private String ac = "1234-DCAB-456A";

    public MockHttpsConnector(CredentialVault vault) {
        this.vault = vault;
    }

    public String postSOAP(String message, URL url) {
        Document doc = XmlUtil.readXml(SignatureUtil.setupCryptoProviderForJVM(), message, false);

        try {
            Request req = new RequestModelBuilder().buildModel(doc);
            Response resp = null;
            if(req instanceof RequestRenewalRequest) {
                RenewalAuthorization r = new RenewalAuthorization();
                r.setReferenceNumber(refNo);
                r.setRenewalAuthorizationCode(ac);
                r.setStatusCode(0);
                r.setStatusText("OK");

                resp = r;
            } else if(req instanceof RenewCertificateRequest) {
                RenewCertificateRequest renewReq = (RenewCertificateRequest)req;
                IssueResult res = new IssueResult();
                if(!renewReq.getReferenceNumber().equals(refNo)) {
                    res.setStatusCode(3);
                    res.setStatusText("Unknown referencenumber");
                    res.setIssuedUserCertificate(new byte[0]);
                    res.setRootCertificate(new byte[0]);
                } else {
                    res.setStatusCode(0);
                    res.setStatusText("OK");
                    res.setIssuedUserCertificate(vault.getSystemCredentialPair().getCertificate().getEncoded());
                    res.setRootCertificate(vault.getSystemCredentialPair().getCertificate().getEncoded());
                }
                resp = res;
            }
            ResponseDOMBuilder builder = new ResponseDOMBuilder(XmlUtil.createEmptyDocument(), resp);
            Document respdoc = builder.buildDocument();

            String xmlstring = XmlUtil.node2String(respdoc, true, true);
            return xmlstring;
        } catch (ModelBuildException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (CredentialVaultException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String post(String message, URL url, Map<String, String> requestProperties) throws IOException {
        throw new IOException("Not supported in this mock");
    }

}
