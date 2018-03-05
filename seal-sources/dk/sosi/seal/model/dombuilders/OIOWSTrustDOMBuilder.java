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

import dk.sosi.seal.model.LibertyMessageDOMEnhancer;
import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Abstract implementation of the <code>AbstractDOMBuilder</code> class.<br />
 * This class extends the <code>AbstractDOMBuilder</code> with functionality used when creates a SOAP message.
 */
public abstract class OIOWSTrustDOMBuilder extends AbstractSOAPBuilder<Document> {

    protected CredentialVault signingVault;

    protected abstract void addExtraHeaders(Document doc, Element header);

    protected abstract void addExtraNamespaceDeclarations(Element envelope);

    protected final void addHeaderContent(Document doc, Element header) {
        final Element action = doc.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.ACTION_PREFIXED);
        header.appendChild(action);
        action.setTextContent(WSTrustConstants.WST_1_3_ISSUE_ACTION);

        final Element messageID = doc.createElementNS(NameSpaces.WSA_1_0_SCHEMA, WSATags.MESSAGE_ID_PREFIXED);
        header.appendChild(messageID);
        messageID.setTextContent(XmlUtil.generateUUID());

        addExtraHeaders(doc, header);
    }

    @Override
    protected void addRootAttributes(Element envelope) {
        addNS(envelope, NameSpaces.NS_SOAP, NameSpaces.SOAP_SCHEMA);
        addNS(envelope, NameSpaces.NS_SAML, NameSpaces.SAML2ASSERTION_SCHEMA);
        addNS(envelope, NameSpaces.NS_WSA, NameSpaces.WSA_1_0_SCHEMA);
        addNS(envelope, NameSpaces.NS_WSP, NameSpaces.WSP_SCHEMA);
        addNS(envelope, NameSpaces.NS_WST, NameSpaces.WST_1_3_SCHEMA);

        addExtraNamespaceDeclarations(envelope);
    }

    /**
     * Build the final response <code>Document</code>.<br />
     * Before the <code>Document</code> is generated all attributes will be validated.<br />
     * <br />
     * A <code>Document</code> is generated each time this method is called. Calling this method multiple times will therefore return multiple objects.
     *
     * @return DOM representation of the Identity token response.
     * @throws dk.sosi.seal.model.ModelException
     *             Thrown if the builder finds a validation problem.
     */
    @Override
    public final Document build() throws ModelException {
        Document document = createDocument();
        if (signingVault != null) {
            LibertyMessageDOMEnhancer enhancer = new LibertyMessageDOMEnhancer(signingVault, document, false);
            enhancer.enhanceAndSign();
        }
        return document;
    }

    protected void addSecurityTokenReferenceToIDCard(Document doc, Element parent) {
        final Element securityTokenReference = doc.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY_TOKEN_REFERENCE_PREFIXED);
        parent.appendChild(securityTokenReference);
        final Element reference = doc.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.REFERENCE_PREFIXED);
        reference.setAttributeNS(null, WSSEAttributes.URI, IDValues.IDCARD_REFERENCE);
        securityTokenReference.appendChild(reference);
    }
}