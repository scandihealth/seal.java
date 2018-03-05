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
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Created by chg on 22/02/2017.
 */
public abstract class AbstractOIOToIdentityTokenRequestDOMBuilder<T extends AbstractOIOToIdentityTokenRequestDOMBuilder> extends OIOWSTrustRequestDOMBuilder {

    protected String cprNumberClaim;

    public T setCPRNumberClaim(String cprNumberClaim) {
        this.cprNumberClaim = cprNumberClaim;
        return (T) this;
    }

    public T setSigningVault(CredentialVault signingVault) {
        this.signingVault = signingVault;
        return (T) this;
    }
    @Override
    protected void validateBeforeBuild() throws ModelException {
        super.validateBeforeBuild();
        validate("CPRNumberClaim", cprNumberClaim);
        validate("signingVault", signingVault);
    }

    @Override
    protected void addExtraNamespaceDeclarations(Element envelope) {
        super.addExtraNamespaceDeclarations(envelope);
        envelope.setAttributeNS(NameSpaces.XMLNS_SCHEMA, NameSpaces.NS_XMLNS + ":" + NameSpaces.NS_WSF_AUTH, NameSpaces.WSF_AUTH_SCHEMA);
    }

    @Override
    protected void addClaims(Document doc, Element requestSecurityToken) {
        Element claimsElm = createElement(WSTTags.claims);
        claimsElm.setAttributeNS(null, WSTrustAttributes.DIALECT, WSFAuthValues.CLAIMS_DIALECT);
        requestSecurityToken.appendChild(claimsElm);

        Element claimTypeElm = createElement(WSFAuthTags.claimType);
        claimTypeElm.setAttributeNS(null, WSFAuthAttributes.URI, OIOSAMLAttributes.CPR_NUMBER);
        claimsElm.appendChild(claimTypeElm);

        Element valueElm = createElement(WSFAuthTags.value);
        valueElm.setTextContent(cprNumberClaim);
        claimTypeElm.appendChild(valueElm);
    }
}
