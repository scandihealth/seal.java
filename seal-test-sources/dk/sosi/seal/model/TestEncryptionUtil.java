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
 * $HeadURL$
 * $Id$
 */

package dk.sosi.seal.model;

import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.CredentialVaultTestUtil;
import dk.sosi.seal.xml.XmlUtil;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.PublicKey;

import static org.junit.Assert.assertEquals;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class TestEncryptionUtil {

    @Test
    public void testSimpleEncryption() {
        String simpleXml = "<root><ToEncrypt><foo>bar</foo></ToEncrypt></root>";
        Document document = XmlUtil.readXml(System.getProperties(), simpleXml, false);
        Element root = document.getDocumentElement();

        CredentialPair credentialPair = CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair();
        PublicKey key = credentialPair.getCertificate().getPublicKey();
        Element toEncrypt = (Element) root.getFirstChild();
        EncryptionUtil.encrypt(toEncrypt, key);

        //System.out.println(XmlUtil.node2String(document, true, true));
        assertEquals("EncryptedData", root.getFirstChild().getLocalName());
        assertEquals("http://www.w3.org/2001/04/xmlenc#Element", ((Element) root.getFirstChild()).getAttribute("Type"));

        EncryptionUtil.decrypt((Element) root.getFirstChild(), credentialPair.getPrivateKey());

        //System.out.println(XmlUtil.node2String(document, true, true));
        assertEquals("ToEncrypt", root.getFirstChild().getLocalName());
    }

    @Test
    public void testDetachedDecryption() {
        String simpleXml = "<root><ToEncrypt><foo>bar</foo></ToEncrypt></root>";
        Document document = XmlUtil.readXml(System.getProperties(), simpleXml, false);
        Element root = document.getDocumentElement();

        CredentialPair credentialPair = CredentialVaultTestUtil.getCredentialVault().getSystemCredentialPair();
        PublicKey key = credentialPair.getCertificate().getPublicKey();
        Element toEncrypt = (Element) root.getFirstChild();
        EncryptionUtil.encrypt(toEncrypt, key);

        //System.out.println(XmlUtil.node2String(document, true, true));
        assertEquals("EncryptedData", root.getFirstChild().getLocalName());
        assertEquals("http://www.w3.org/2001/04/xmlenc#Element", ((Element) root.getFirstChild()).getAttribute("Type"));

        Element decryptedDetached = EncryptionUtil.decryptAndDetach((Element) root.getFirstChild(), credentialPair.getPrivateKey());

        //System.out.println(XmlUtil.node2String(decryptedDetached, true, true));
        assertEquals("ToEncrypt", decryptedDetached.getLocalName());
    }

}
