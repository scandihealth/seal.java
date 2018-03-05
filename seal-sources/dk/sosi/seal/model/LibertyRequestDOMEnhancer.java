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

import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import java.io.IOException;
import java.util.List;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class LibertyRequestDOMEnhancer extends LibertyMessageDOMEnhancer {

    private static Schema schema;

    private IdentityToken identityToken;

    public LibertyRequestDOMEnhancer(CredentialVault credentialVault, Document document) {
        super(credentialVault, document, true);
        if (credentialVault == null) throw new IllegalArgumentException("CredentialVault cannot be null");
        if (document == null) throw new IllegalArgumentException("Document cannot be null");

        schemaValidate(document);
    }

    /**
     * Required, no checks are performed on the token
     *
     * @param identityToken
     */
    public void setIdentityToken(IdentityToken identityToken) {
        if (identityToken == null) {
            throw new IllegalArgumentException("'identityToken' cannot be null");
        }
        this.identityToken = identityToken;
    }

    @Override
    protected void addTokenToSecurityHeader(Element securityHeader, List<SignatureConfiguration.Reference> references) {
        String securityTokenReferenceID = addIdentityTokenAndCorrespondingSecurityTokenReference(securityHeader);
        references.add(new SignatureConfiguration.Reference(securityTokenReferenceID, SignatureConfiguration.Type.SECURITY_TOKEN_REFERENCE));
    }

    @Override
    protected void checkBeforeEnhancing(Element header) {
        checkIdentityTokenSet();
        checkForOldWSAddressingVersion(header);
        checkForExistingWSSecurityHeader(header);
    }

    private void checkIdentityTokenSet() throws ModelBuildException {
        if (identityToken == null) {
            throw new ModelBuildException("IdentityToken must be set!");
        }
    }

    private void checkForOldWSAddressingVersion(Element header) throws ModelException {
        final String message = "Document contains WS-Addressing headers in '" + NameSpaces.WSA_SCHEMA
                + "' namespace. Only WS-Addressing 1.0 (namespace '" + NameSpaces.WSA_1_0_SCHEMA + "') supported as required "
                + "by the Liberty Basic SOAP Binding is supported.";
        checkForElementWithNamespace(header, NameSpaces.WSA_SCHEMA, message);
    }

    private void checkForExistingWSSecurityHeader(Element header) throws ModelException {
        checkForElementWithNamespace(header, NameSpaces.WSSE_SCHEMA, "Document already contains a WS-Security header!");
    }

    private void checkForElementWithNamespace(Element element, String namesSpace, String errorMessage) throws ModelException {
        final NodeList childNodes = element.getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            if (namesSpace.equals(childNodes.item(i).getNamespaceURI())) {
                throw new ModelException(errorMessage);
            }
        }
    }

    private String addIdentityTokenAndCorrespondingSecurityTokenReference(Element securityHeader) {
        securityHeader.appendChild(document.importNode(identityToken.getDOM().getDocumentElement(), true));

        final Element securityTokenReference = document.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.SECURITY_TOKEN_REFERENCE_PREFIXED);
        securityTokenReference.setAttributeNS(NameSpaces.WSSE_1_1_SCHEMA, WSSE11Attributes.TOKEN_TYPE_PREFIXED, WSSEValues.SAML_TOKEN_TYPE);
        securityHeader.appendChild(securityTokenReference);

        final Element keyIdentifier = document.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.KEY_IDENTIFIER_PREFIXED);
        keyIdentifier.setAttributeNS(null, WSSEAttributes.VALUE_TYPE, WSSEValues.VALUE_TYPE_SAML_ID);
        keyIdentifier.setTextContent(identityToken.getID());
        securityTokenReference.appendChild(keyIdentifier);
        return ensureIdAttribute(securityTokenReference, "str");
    }

    private void schemaValidate(Document envelope) {
        try {
            final Validator validator = getSchema().newValidator();
            validator.validate(new DOMSource(envelope));
        } catch (SAXException e) {
            throw new ModelBuildException("Error validating SOAP message", e);
        } catch (IOException e) {
            throw new ModelBuildException("Error validating SOAP message", e);
        }

    }

    private static synchronized Schema getSchema() throws SAXException {
        if (schema == null) {
            schema = SchemaUtil.loadSchema("/liberty/req/standard-soap.xsd");
        }
        return schema;
    }

}
