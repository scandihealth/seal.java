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
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.constants.SAMLTags;
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.PublicKey;

/**
 * Created by chg on 21/02/2017.
 */
public abstract class AbstractOIOToIdentityTokenResponseDOMBuilder<T extends AbstractOIOToIdentityTokenResponseDOMBuilder> extends AbstractIdentityTokenResponseDOMBuilder {

    private PublicKey encryptionKey;

    public T setSigningVault(CredentialVault signingVault) {
        super.signingVault = signingVault;
        return (T) this;
    }

    public T setEncryptionKey(PublicKey encryptionKey) {
        this.encryptionKey = encryptionKey;
        return (T) this;
    }

    @Override
    protected void validateBeforeBuild() {
        super.validateBeforeBuild();
        validate("signingVault", signingVault);
    }

    @Override
    protected Element getIssuedTokenDOMElement() {
        Document assertionDoc = identityToken.getDOM();
        Element assertionElm = assertionDoc.getDocumentElement();
        if (encryptionKey != null) {
            Element encryptedAssertionElm = assertionDoc.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ENCRYPTED_ASSERTION_PREFIXED);
            encryptedAssertionElm.appendChild(assertionElm);
            EncryptionUtil.encrypt(assertionElm, encryptionKey);
            return encryptedAssertionElm;
        } else {
            return assertionElm;
        }
    }
}
