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
import dk.sosi.seal.model.SignatureConfiguration;
import dk.sosi.seal.model.SignatureUtil;
import dk.sosi.seal.model.UserIDCard;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.pki.SignatureProviderFactory;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Date;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public abstract class AbstractOIOSAMLTokenBuilder<S extends AbstractOIOSAMLTokenBuilder, T> extends AbstractSAMLBuilder<S, T> {

    private CredentialVault signingVault;

    private String audienceRestriction;
    private Date notBefore;
    private Date notOnOrAfter;
    private Node subjectNode;

    protected UserIDCard userIdCard;
    protected boolean extractCprNumber;
    protected boolean extractCvrNumberIdentifier;
    protected boolean extractOrganizationName;
    protected boolean extractITSystemName;
    protected boolean extractUserAuthorizationCode;
    protected boolean extractUserEducationCode;

    /**
     * <b>Mandatory</b>: Set the audience restriction part of the message.<br />
     * Example:
     *
     * <pre>
     *  &lt;saml:Conditions ... &gt;
     *      &lt;saml:AudienceRestriction&gt;http://fmk-online.dk&lt;/saml:AudienceRestriction&gt;
     *  &lt;/saml:Conditions&gt;
     * </pre>
     *
     * @param audienceRestriction
     *            The <code>audienceRestriction</code> value.
     * @return The <code>S extends AbstractOIOSAMLTokenBuilder</code> instance.
     */
    public S setAudienceRestriction(String audienceRestriction) {
        this.audienceRestriction = audienceRestriction;
        return (S) this;
    }

    /**
     * <b>Mandatory</b>: Set the date/time when the oiosaml token is valid from.<br />
     * Example:
     *
     * <pre>
     *  &lt;saml:Conditions NotBefore="2011-07-23T15:32:12Z" ... &gt;
     *      ...
     *  &lt;/saml:Conditions&gt;
     * </pre>
     *
     * @param notBefore
     *            The beginning of the validity period
     * @return The <code>S extends AbstractOIOSAMLTokenBuilder</code> instance.
     */
    public S setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
        return (S) this;
    }

    /**
     * <b>Mandatory</b>: Set the date/time when the oiosaml token expires.<br />
     * Example:
     *
     * <pre>
     *  &lt;saml:Conditions ... NotOnOrAfter="2011-07-23T15:32:12Z"&gt;
     *      ...
     *  &lt;/saml:Conditions&gt;
     * </pre>
     *
     * @param notOnOrAfter
     *            The date/time of expiration.
     * @return The <code>S extends AbstractOIOSAMLTokenBuilder</code> instance.
     */
    public S setNotOnOrAfter(Date notOnOrAfter) {
        this.notOnOrAfter = notOnOrAfter;
        return (S) this;
    }

    /**
     * <b>Mandatory</b>: Set the UserIdCard from which attributes for the oiosaml token are extracted.
     *
     * @param userIdCard
     *            The UserIdCard.
     * @return The <code>S extends AbstractOIOSAMLTokenBuilder</code> instance.
     */
    public S setUserIdCard(UserIDCard userIdCard) {
        this.userIdCard = userIdCard;
        return (S) this;
    }

    public S setSigningVault(CredentialVault signingVault) {
        this.signingVault = signingVault;
        return (S) this;
    }


    @Override
    protected void validateBeforeBuild() {
        super.validateBeforeBuild();
        validate("userIdCard", userIdCard);
        validate("notBefore", notBefore);
        validate("audienceRestriction", audienceRestriction);
        validate("notOnOrAfter", notOnOrAfter);
        validate("signingVault", signingVault);

        if(!notBefore.before(notOnOrAfter)) {
            throw new ModelException("notBefore is after notOnOrAfter");
        }
    }

    @Override
    protected final void appendToRoot(Document doc, Element root) {
        super.appendToRoot(doc, root);
        subjectNode = createSubject();
        root.appendChild(subjectNode);
        root.appendChild(createConditions());
        root.appendChild(createAuthnStatement());
        root.appendChild(createAttributeStatement(doc));
    }

    protected abstract Node createSubject();

    private Element createAttributeStatement(Document doc) {
        Element attributeStatementElm = createElement(SAMLTags.attributeStatement);
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.SURNAME, OIOSAMLAttributes.SURNAME_FRIENDLY, userIdCard.getUserInfo().getSurName()));
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.COMMON_NAME, OIOSAMLAttributes.COMMON_NAME_FRIENDLY, userIdCard.getUserInfo().getGivenName() + " " + userIdCard.getUserInfo().getSurName()));
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.EMAIL, OIOSAMLAttributes.EMAIL_FRIENDLY, userIdCard.getUserInfo().getEmail()));
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.ASSURANCE_LEVEL, null, SAMLValues.ASSURANCELEVEL_3));
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.SPEC_VERSION, null, SAMLValues.DK_SPEC_VERSION));
        if(extractCvrNumberIdentifier) {
            if(!SubjectIdentifierTypeValues.CVR_NUMBER.equals(userIdCard.getSystemInfo().getCareProvider().getType())) {
                throw new IllegalArgumentException("CVR no. not provided in CareProvider - was " + userIdCard.getSystemInfo().getCareProvider().getType());
            }
            attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.CVR_NUMBER, null, userIdCard.getSystemInfo().getCareProvider().getID()));
        }
        if(extractOrganizationName) {
            attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.ORGANIZATION_NAME, OIOSAMLAttributes.ORGANIZATION_NAME_FRIENDLY, userIdCard.getSystemInfo().getCareProvider().getOrgName()));
        }
        if(extractCprNumber) {
            attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.CPR_NUMBER, null, userIdCard.getUserInfo().getCPR()));
        }
        if(extractUserAuthorizationCode) {
            if(userIdCard.getUserInfo().getAuthorizationCode() == null) {
                throw new IllegalArgumentException("UserAuthorizationCode missing in UserIdCard - cannot create OIOSAML Token with UserAuthorizationCode");
            }
            attributeStatementElm.appendChild(createAttributeElement(HealthcareSAMLAttributes.USER_AUTHORIZATION_CODE, null, userIdCard.getUserInfo().getAuthorizationCode()));
        }
        if(extractITSystemName) {
            attributeStatementElm.appendChild(createAttributeElement(HealthcareSAMLAttributes.IT_SYSTEM_NAME, null, userIdCard.getSystemInfo().getITSystemName()));
        }
        if(extractUserEducationCode) {
            if(userIdCard.getUserInfo().getAuthorizationCode() == null) {
                throw new IllegalArgumentException("UserAuthorizationCode must also be set on UserIdCard in order to treat contents of UserRole as UserEducationCode");
            }
            attributeStatementElm.appendChild(createAttributeElement(HealthcareSAMLAttributes.USER_EDUCATION_CODE, null, userIdCard.getUserInfo().getRole()));
        }
        addExtraAttributes(doc, attributeStatementElm);
        return attributeStatementElm;
    }

    private Node createAuthnStatement() {
        Element authnStatementElm = createElement(SAMLTags.authnStatement);
        authnStatementElm.setAttributeNS(null, SAMLAttributes.AUTHN_INSTANT, XmlUtil.getDateFormat(true).format(userIdCard.getCreatedDate()));

        Element authnContextElm = createElement(SAMLTags.authnContext);
        Element authContextClassRefElm = createElement(SAMLTags.authnContextClassRef);
        authContextClassRefElm.setTextContent(SAMLValues.AUTHN_CONTEXT_CLASS_REF);
        authnContextElm.appendChild(authContextClassRefElm);
        authnStatementElm.appendChild(authnContextElm);
        addExtraAuthnAttributes(authnStatementElm);
        return authnStatementElm;
    }

    private Node createConditions() {
        Element conditionsElm = createElement(SAMLTags.conditions);
        conditionsElm.setAttributeNS(null, SAMLAttributes.NOT_BEFORE, XmlUtil.getDateFormat(true).format(notBefore));
        conditionsElm.setAttributeNS(null, SAMLAttributes.NOT_ON_OR_AFTER, XmlUtil.getDateFormat(true).format(notOnOrAfter));

        Element audienceRestrictionElm = createElement(SAMLTags.audienceRestriction);
        conditionsElm.appendChild(audienceRestrictionElm);

        Element audienceElm = createElement(SAMLTags.audience);
        audienceElm.setTextContent(audienceRestriction);
        audienceRestrictionElm.appendChild(audienceElm);

        return conditionsElm;
    }

    protected void signAssertion(Document document) {
        SignatureConfiguration signatureConfiguration = new SignatureConfiguration(new String[] { assertionID }, assertionID, IDValues.Id);
        signatureConfiguration.setSignatureSiblingNode(subjectNode);
        addExtraSignatureConfiguration(signatureConfiguration);

        SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(signingVault), document, signatureConfiguration);
    }

    protected void addExtraSignatureConfiguration(SignatureConfiguration signatureConfiguration) {
    }

    protected void addExtraAttributes(Document doc, Element attributeStatementElm) {
    }

    protected void addExtraAuthnAttributes(Element authnStatementElm) {
    }
}
