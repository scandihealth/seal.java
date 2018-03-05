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

import dk.sosi.seal.model.IDCard;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.WSTTags;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Date;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOSAMLAssertionToIDCardResponseDOMBuilder extends OIOWSTrustResponseDOMBuilder<OIOSAMLAssertionToIDCardResponseDOMBuilder> {


    private final static String SOSI_FEDERATION = "http://sosi.dk";

    private IDCard idCard;

    public OIOSAMLAssertionToIDCardResponseDOMBuilder setIDCard(IDCard idCard) {
        this.idCard = idCard;
        return this;
    }

    public OIOSAMLAssertionToIDCardResponseDOMBuilder setSigningVault(CredentialVault signingVault) {
        this.signingVault = signingVault;
        return this;
    }

    @Override
    protected void validateBeforeBuild() {
        super.validateBeforeBuild();
        validate("signingVault", signingVault);
        if (! isFault) {
            validate("idCard", idCard);
        }
    }

    @Override
    protected void appendAdditionalToResponseCollection(Document doc, Element responseCollectionElm) {
        super.appendAdditionalToResponseCollection(doc, responseCollectionElm);
        Element requestedAttachedReference = doc.createElementNS(NameSpaces.WST_1_3_SCHEMA, WSTTags.REQUESTED_ATTACHED_REFERENCE_PREFIXED);
        responseCollectionElm.appendChild(requestedAttachedReference);
        addSecurityTokenReferenceToIDCard(doc, requestedAttachedReference);

        Element requestedUnattachedReference = doc.createElementNS(NameSpaces.WST_1_3_SCHEMA, WSTTags.REQUESTED_UNATTACHED_REFERENCE_PREFIXED);
        responseCollectionElm.appendChild(requestedUnattachedReference);
        addSecurityTokenReferenceToIDCard(doc, requestedUnattachedReference);
    }

    @Override
    protected String getAudienceRestriction() {
        return SOSI_FEDERATION;
    }

    @Override
    protected Element getIssuedTokenDOMElement() {
        return idCard.serialize2DOMDocument(null, XmlUtil.createEmptyDocument());
    }

    @Override
    protected Date getIssuedTokenNotBefore() {
        return idCard.getCreatedDate();
    }

    @Override
    protected Date getIssuedTokenNotOnOrAfter() {
        return idCard.getExpiryDate();
    }
}
