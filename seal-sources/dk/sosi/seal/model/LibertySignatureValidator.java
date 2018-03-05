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
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.List;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class LibertySignatureValidator extends AbstractDOMInfoExtractor {

    private CredentialVault vault;
    private Federation federation;

    private boolean requireFrameworkHeader;
    private boolean requireWSAddressingRelatesTo;
    private boolean requireReferenceToIdentityToken;

    public LibertySignatureValidator(CredentialVault vault, Element dom) {
        super(dom);
        this.vault = vault;
    }

    public LibertySignatureValidator(Federation federation, Element dom) {
        super(dom);
        this.federation = federation;
    }

    public LibertySignatureValidator requireFrameworkHeader() {
        requireFrameworkHeader = true;
        return this;
    }

    public LibertySignatureValidator requireWSAddressingRelatesTo() {
        requireWSAddressingRelatesTo = true;
        return this;
    }

    public LibertySignatureValidator requireReferenceToIdentityToken() {
        requireReferenceToIdentityToken = true;
        return this;
    }

    public void validateSignature() throws ModelBuildException {
        internalValidate(false);
    }

    public void validateSignatureAndTrust() throws ModelBuildException {
        internalValidate(true);
    }

    private void internalValidate(boolean checkTrust) {
        final Element signatureElement = getLibertySignatureElement();
        if (!SignatureUtil.validate(signatureElement, federation, vault, checkTrust)) {
            throw new ModelBuildException("Liberty signature could not be validated");
        }

        final List<Element> dereferencedSignedElements = SignatureUtil.dereferenceSignedElements(signatureElement);

        final Element messageID = getWSAddressingMessageIDElement();
        validateIsReferenced(messageID, dereferencedSignedElements);

        final Element action = getWSAddressingActionElement();
        validateIsReferenced(action, dereferencedSignedElements);

        final Element to = getWSAddressingToElement();
        if (to != null) {
            validateIsReferenced(to, dereferencedSignedElements);
        }

        final Element relatesTo = getWSAddressingRelatesToElement();
        if (requireWSAddressingRelatesTo || relatesTo != null) {
            validateIsReferenced(relatesTo, dereferencedSignedElements);
        }

        if (requireFrameworkHeader) {
            final Element framework = getLibertyFrameworkElement();
            validateIsReferenced(framework, dereferencedSignedElements);
        }

        final Element timestamp = getTimestampElement();
        validateIsReferenced(timestamp, dereferencedSignedElements);

        if (requireReferenceToIdentityToken) {
            final Element securityTokenReference = getSecurityTokenReferenceElement();
            validateIsReferenced(securityTokenReference, dereferencedSignedElements);
            validateReferenceToIdentityToken(securityTokenReference);
        }

        final Element bodyElement = getBodyElement();
        validateIsReferenced(bodyElement, dereferencedSignedElements);
    }

    private void validateReferenceToIdentityToken(Element securityTokenReference) {
        final Element keyIdentifier = XmlUtil.getFirstChildElementNS(securityTokenReference, NameSpaces.WSSE_SCHEMA, WSSETags.KEY_IDENTIFIER);
        if (keyIdentifier == null) {
            throw new ModelBuildException("Could not find KeyIdentifier element in SecurityTokenReference");
        }
        final Node token = XmlUtil.getElementByIdExtended(dom, keyIdentifier.getTextContent());
        if (!getTag(SOAPTags.envelope, SOAPTags.header, WSSETags.security, SAMLTags.assertion).equals(token)) {
            throw new ModelBuildException("SecurityTokenReference is not referencing IdentityToken");
        }
    }

    private void validateIsReferenced(Element element, List<Element> references) {
        if (!references.contains(element)) {
            throw new ModelBuildException("Missing Liberty signature on element " + element.getNamespaceURI() + "#" + element.getLocalName());
        }
    }

    private Element getLibertySignatureElement() {
        final Element signature = getTag(SOAPTags.envelope, SOAPTags.header, WSSETags.security, DSTags.signature);
        if (signature == null) {
            throw new ModelBuildException("Could not find Liberty signature element");
        }
        return signature;
    }

    private Element getWSAddressingMessageIDElement() {
        final Element messageID = getTag(SOAPTags.envelope, SOAPTags.header, WSATags.messageID);
        if (messageID == null) {
            throw new ModelBuildException("Could not find WS-Addressing 1.0 MessageID element");
        }
        return messageID;
    }


    private Element getWSAddressingActionElement() {
        final Element action = getTag(SOAPTags.envelope, SOAPTags.header, WSATags.action);
        if (action == null) {
            throw new ModelBuildException("Could not find WS-Addressing 1.0 Action element");
        }
        return action;
    }

    private Element getWSAddressingToElement() {
        return getTag(SOAPTags.envelope, SOAPTags.header, WSATags.to);
    }

    private Element getWSAddressingRelatesToElement() {
        return getTag(SOAPTags.envelope, SOAPTags.header, WSATags.relatesTo);
    }

    private Element getLibertyFrameworkElement() {
        final Element framework = getTag(SOAPTags.envelope, SOAPTags.header, LibertyTags.framework);
        if (framework == null) {
            throw new ModelBuildException("Could not find Liberty Framework element");
        }
        return framework;
    }

    private Element getTimestampElement() {
        final Element timestamp = getTag(SOAPTags.envelope, SOAPTags.header, WSSETags.security, WSUTags.timestamp);
        if (timestamp == null) {
            throw new ModelBuildException("Could not find Timestamp element");
        }
        return timestamp;
    }

    private Element getSecurityTokenReferenceElement() {
        final Element securityTokenReference = getTag(SOAPTags.envelope, SOAPTags.header, WSSETags.security, WSSETags.securityTokenReference);
        if (securityTokenReference == null) {
            throw new ModelBuildException("Could not find SecurityTokenReference element");
        }
        return securityTokenReference;
    }

    private Element getBodyElement() {
        final Element body = getTag(SOAPTags.envelope, SOAPTags.body);
        if (body == null) {
            throw new ModelBuildException("Could not find Body element");
        }
        return body;
    }

}
