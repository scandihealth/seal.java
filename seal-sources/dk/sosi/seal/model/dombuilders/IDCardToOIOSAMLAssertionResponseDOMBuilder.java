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

import dk.sosi.seal.model.EncryptionUtil;
import dk.sosi.seal.model.OIOSAMLAssertion;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SAMLTags;
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.PublicKey;
import java.util.Date;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class IDCardToOIOSAMLAssertionResponseDOMBuilder extends OIOWSTrustResponseDOMBuilder<IDCardToOIOSAMLAssertionResponseDOMBuilder>{

    private PublicKey encryptionKey;
    private OIOSAMLAssertion assertion;

    public IDCardToOIOSAMLAssertionResponseDOMBuilder setEncryptionKey(PublicKey encryptionKey) {
        this.encryptionKey = encryptionKey;
        return this;
    }

    public IDCardToOIOSAMLAssertionResponseDOMBuilder setOIOSAMLAssertion(OIOSAMLAssertion assertion) {
        this.assertion = assertion;
        return this;
    }

    public IDCardToOIOSAMLAssertionResponseDOMBuilder setSigningVault(CredentialVault signingVault) {
        this.signingVault = signingVault;
        return this;
    }

    @Override
    protected void validateBeforeBuild() {
        super.validateBeforeBuild();
        validate("signingVault", signingVault);
        if (!isFault) {
            validate("encryptionKey", encryptionKey);
            validate("assertion", assertion);
        }
    }

    @Override
    protected String getAudienceRestriction() {
        return assertion.getAudienceRestriction();
    }

    @Override
    protected Element getIssuedTokenDOMElement() {
        Document assertionDoc = assertion.getDOM();
        Element assertionElm = assertionDoc.getDocumentElement();
        Element encryptedAssertionElm = assertionDoc.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ENCRYPTED_ASSERTION_PREFIXED);
        encryptedAssertionElm.appendChild(assertionElm);
        EncryptionUtil.encrypt(assertionElm, encryptionKey);
        return encryptedAssertionElm;
    }

    @Override
    protected Date getIssuedTokenNotBefore() {
        return assertion.getNotBefore();
    }

    @Override
    protected Date getIssuedTokenNotOnOrAfter() {
        return assertion.getNotOnOrAfter();
    }
}
