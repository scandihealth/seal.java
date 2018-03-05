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
import org.w3c.dom.Node;

import java.util.Date;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public abstract class AbstractSAMLBuilder<S extends AbstractSAMLBuilder, T> extends AbstractDOMBuilder<T>{

    private String issuer;

    protected String assertionID;

    /**
     * <b>Mandatory</b>: Set the issuer part of the message.<br />
     * Example:
     *
     * <pre>
     *  &lt;saml:Assertion ... &gt;
     *   &lt;saml:Issuer&gt;http://pan.certifikat.dk/sts/services/SecurityTokenService&lt;/saml:Issuer&gt;
     *   ...
     *  &lt;/saml:Assertion ... &gt;
     * </pre>
     *
     * @param issuer
     *            The <code>issuer</code> value.
     * @return The <code>S extends AbstractSAMLBuilder</code> instance.
     */
    public S setIssuer(String issuer) {
        this.issuer = issuer;
        return (S) this;
    }

    @Override
    protected void validateBeforeBuild() throws ModelException {
        validate("issuer", issuer);
    }

    @Override
    protected void appendToRoot(Document doc, Element root) {
        root.appendChild(createIssuer());
    }

    private Node createIssuer() {
        Element issuerElm = createElement(SAMLTags.issuer);
        issuerElm.setTextContent(issuer);
        return issuerElm;
    }

    @Override
    protected Element createRoot(Document doc) {
        return createElement(SAMLTags.assertion);
    }

    @Override
    protected void addRootAttributes(Element root) {
        root.setAttributeNS(null, SAMLAttributes.ISSUE_INSTANT, XmlUtil.getDateFormat(true).format(new Date()));
        assertionID = XmlUtil.generateRandomNCName();
        root.setAttributeNS(null, SAMLAttributes.ID, assertionID);
        root.setAttributeNS(null, SAMLAttributes.VERSION, SAMLValues.SAML_VERSION);

        addNS(root, NameSpaces.NS_SAML, NameSpaces.SAML2ASSERTION_SCHEMA);
        addNS(root, NameSpaces.NS_DS, NameSpaces.DSIG_SCHEMA);
        addNS(root, NameSpaces.NS_XSI, NameSpaces.XMLSCHEMAINSTANCE_SCHEMA);
        addNS(root, NameSpaces.NS_XS, NameSpaces.XSD_SCHEMA);
    }

    protected Element createAttributeElement(String name, String friendlyName, String value) {
        Element attributeElm = createElement(SAMLTags.attribute);
        attributeElm.setAttributeNS(null, SAMLAttributes.NAME_FORMAT, SAMLValues.NAME_FORMAT_BASIC);
        attributeElm.setAttributeNS(null, SAMLAttributes.NAME, name);
        if(friendlyName != null) {
            attributeElm.setAttributeNS(null, SAMLAttributes.FRIENDLY_NAME, friendlyName);
        }

        Element attributeValue = createElement(SAMLTags.attributeValue);
        attributeValue.setAttributeNS(NameSpaces.XMLSCHEMAINSTANCE_SCHEMA, XSIAttributes.TYPE_PREFIXED, XSAttributes.STRING_PREFIXED);
        attributeValue.setTextContent(value);
        attributeElm.appendChild(attributeValue);

        return attributeElm;
    }
}