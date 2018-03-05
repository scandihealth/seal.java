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
import dk.sosi.seal.model.OIOSAMLAssertion;
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOSAMLAssertionToIDCardRequestDOMBuilder extends OIOWSTrustRequestDOMBuilder<OIOSAMLAssertionToIDCardRequestDOMBuilder>{

    private static final String SOSI_FEDERATION = "http://sosi.dk";

    private OIOSAMLAssertion assertion;
    private String userAuthorizationCode;
    private String userEducationCode;
    private String userGivenName;
    private String userSurName;
    private String itSystemName;

    public OIOSAMLAssertionToIDCardRequestDOMBuilder() {
        super();
        this.audience = SOSI_FEDERATION;
    }

    public OIOSAMLAssertionToIDCardRequestDOMBuilder setOIOSAMLAssertion(OIOSAMLAssertion assertion) {
        this.assertion = assertion;
        return this;
    }

    public OIOSAMLAssertionToIDCardRequestDOMBuilder setUserAuthorizationCode(String userAuthorizationCode) {
        this.userAuthorizationCode = userAuthorizationCode;
        return this;
    }

    public OIOSAMLAssertionToIDCardRequestDOMBuilder setUserEducationCode(String userEducationCode) {
        this.userEducationCode = userEducationCode;
        return this;
    }

    public OIOSAMLAssertionToIDCardRequestDOMBuilder setUserGivenName(String userGivenName) {
        this.userGivenName = userGivenName;
        return this;
    }

    public OIOSAMLAssertionToIDCardRequestDOMBuilder setUserSurName(String userSurName) {
        this.userSurName = userSurName;
        return this;
    }

    public OIOSAMLAssertionToIDCardRequestDOMBuilder setITSystemName(String itSystemName) {
        this.itSystemName = itSystemName;
        return this;
    }

    public OIOSAMLAssertionToIDCardRequestDOMBuilder setSigningVault(CredentialVault signingVault) {
        this.signingVault = signingVault;
        return this;
    }

    @Override
    protected void validateBeforeBuild() throws ModelException {
        super.validateBeforeBuild();
        validate("OIOSAMLAssertion", assertion);
        validate("itSystemName", itSystemName);
        validate("signingVault", signingVault);
        validateValue("userAuthorizationCode", userAuthorizationCode);
        validateValue("userRole", userEducationCode);
        validateValue("userGivenName", userGivenName);
        validateValue("userSurName", userSurName);
    }

    @Override
    protected void addActAsTokens(Document doc, Element actAs) {
        addOIOSAMLAssertion(doc, actAs);
        addHealthcareContextToken(doc, actAs);
    }

    private void addOIOSAMLAssertion(Document doc, Element actAs) {
        actAs.appendChild(doc.importNode(assertion.getDOM().getDocumentElement(), true));
    }

    private void addHealthcareContextToken(Document doc, Element actAs) {
        HealthcareContextTokenDOMBuilder builder = new HealthcareContextTokenDOMBuilder();
        builder.setIssuer(itSystemName);
        builder.setITSystemName(itSystemName);
        builder.setSubjectNameID(assertion.getSubjectNameID());
        builder.setSubjectNameIDFormat(assertion.getSubjectNameIDFormat());
        if (userAuthorizationCode != null) builder.setUserAuthorizationCode(userAuthorizationCode);
        if (userEducationCode != null) builder.setUserEducationCode(userEducationCode);
        if (userGivenName != null) builder.setUserGivenName(userGivenName);
        if (userSurName != null) builder.setUserSurName(userSurName);
        Document contextTokenDOM = builder.build();
        actAs.appendChild(doc.importNode(contextTokenDOM.getDocumentElement(), true));
    }

}
