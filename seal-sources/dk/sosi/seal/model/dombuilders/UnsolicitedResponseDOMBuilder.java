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

package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Date;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class UnsolicitedResponseDOMBuilder extends AbstractDOMBuilder<Document> {

    private String issuer;
    private Element encryptedAssertion;
    private boolean randomInResponseToRequired;

    public UnsolicitedResponseDOMBuilder setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public UnsolicitedResponseDOMBuilder setEncryptedAssertion(Element encryptedAssertion) {
        this.encryptedAssertion = encryptedAssertion;
        return this;
    }

    public UnsolicitedResponseDOMBuilder requireRandomInResponseTo() {
        this.randomInResponseToRequired = true;
        return this;
    }

    @Override
    public Document build() throws ModelException {
        return createDocument();
    }

    @Override
    protected Element createRoot(Document doc) {
        Element responseElm = createElement(SAMLProtocolTags.response);
        responseElm.setAttributeNS(null, SAMLAttributes.ISSUE_INSTANT, XmlUtil.getDateFormat(true).format(new Date()));
        responseElm.setAttributeNS(null, SAMLAttributes.ID, XmlUtil.generateRandomNCName());
        responseElm.setAttributeNS(null, SAMLAttributes.VERSION, SAMLValues.SAML_VERSION);
        if (randomInResponseToRequired) {
            responseElm.setAttributeNS(null, SAMLAttributes.IN_RESPONSE_TO, XmlUtil.generateRandomNCName());
        }
        return responseElm;
    }

    @Override
    protected void addRootAttributes(Element root) {
        addNS(root, NameSpaces.NS_SAMLP, NameSpaces.SAML2PROTOCOL_SCHEMA);
        addNS(root, NameSpaces.NS_SAML, NameSpaces.SAML2ASSERTION_SCHEMA);
        addNS(root, NameSpaces.NS_DS, NameSpaces.DSIG_SCHEMA);
    }

    @Override
    protected void appendToRoot(Document localDoc, Element root) {
        Element issuerElm = createElement(SAMLTags.issuer);
        issuerElm.setTextContent(issuer);
        root.appendChild(issuerElm);

        Element statusElm = createElement(SAMLProtocolTags.status);
        root.appendChild(statusElm);
        Element statusCodeElm = createElement(SAMLProtocolTags.statusCode);
        statusCodeElm.setAttributeNS(null, SAMLAttributes.VALUE, SAMLValues.STATUS_SUCCESS);
        statusElm.appendChild(statusCodeElm);

        root.appendChild(localDoc.importNode(encryptedAssertion, true));
    }

    @Override
    protected void validateBeforeBuild() throws ModelException {
        validate("issuer", issuer);
        validate("encryptedAssertion", encryptedAssertion);
    }
}
