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

import dk.sosi.seal.model.constants.SAMLAttributes;
import dk.sosi.seal.model.constants.SAMLTags;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.List;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class AbstractSAMLToken extends AbstractDOMInfoExtractor{

    public AbstractSAMLToken(Element dom) {
        super(dom);
    }

    /**
     * Extract the <code>ID</code> attribute from the <code>saml:Assertion</code> value from the DOM.<br />
     *
     * <pre>
     *   &lt;saml:Assertion ... &gt; ID="..." ... &lt;/saml:Assertion&gt;
     * </pre>
     *
     * @return The ID attribute value of the <code>saml:Assertion</code> tag.
     */
    public String getID() {
        return safeGetAttribute(SAMLAttributes.ID, SAMLTags.assertion);
    }

    /**
     * Extract the issuer part of the token.<br />
     *
     * <pre>
     *  &lt;saml:Assertion ... &gt;
     *   &lt;saml:Issuer&gt;http://pan.certifikat.dk/sts/services/SecurityTokenService&lt;/saml:Issuer&gt;
     *   ...
     *  &lt;/saml:Assertion ... &gt;
     * </pre>
     *
     * @return The issuer of the SAML token.
     */
    public String getIssuer() {
        Element ac = getTag(SAMLTags.assertion, SAMLTags.issuer);
        return ac != null ? ac.getTextContent().trim() : null;
    }

    /**
     * Extract the value of a SAML attribute with from the DOM.<br />
     *
     * @param attributeName The name of the SAML attribute to retrieve
     *
     * @return The value of the first SAML attribute matching the name or null if no match is found.
     */
    public String getAttribute(String attributeName) {
        Element attributeElm = getAttributeElement(attributeName);
        if (attributeElm == null) {
            return null;
        }
        return attributeElm.getTextContent().trim();
    }

    /**
     * Retrieve the underlying DOM model of the <code>AbstractSAMLToken</code>.<br />
     * <b>Warning</b>: The returned DOM model is a clone of the underlying model,<br />
     * and hence all modifications done to the DOM model will <u>not</u> reflect back to the <code>AbstractSAMLToken</code>.
     *
     * @return <code>Document</code> containing the DOM model.
     */
    public Document getDOM() {
        Document doc = XmlUtil.createEmptyDocument();
        Node root = doc.importNode(dom, true);
        doc.appendChild(root);
        return doc;
    }

    protected Element getAttributeElement(String attributeName) {
        List<Element> nl = getTags(SAMLTags.assertion, SAMLTags.attributeStatement, SAMLTags.attribute);
        return getFilteredElement(nl, SAMLAttributes.NAME, attributeName);
    }
}
