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
import dk.sosi.seal.model.dombuilders.AbstractSAMLBuilder;
import dk.sosi.seal.pki.SignatureProviderFactory;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by chg on 20/02/2017.
 */
public class CitizenIdentityTokenBuilder extends AbstractSAMLBuilder<CitizenIdentityTokenBuilder,IdentityToken> {

    // TODO This class copies a lot of code from AbstractOIOSAMLTokenBuilder. Class hierarchy should be refactored!

    private String audienceRestriction;
    private Date notBefore;
    private Date notOnOrAfter;
    private String cprNumber;
    private String subjectNameID;
    private String subjectNameIDFormat;
    private String recipientURL;
    private Date deliveryNotOnOrAfter;
    private X509Certificate holderOfKeyCertificate;

    private CredentialVault signingVault;

    private Node subjectNode;

    public CitizenIdentityTokenBuilder setAudienceRestriction(String audienceRestriction) {
        this.audienceRestriction = audienceRestriction;
        return this;
    }

    public CitizenIdentityTokenBuilder setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
        return this;
    }

    public CitizenIdentityTokenBuilder setNotOnOrAfter(Date notOnOrAfter) {
        this.notOnOrAfter = notOnOrAfter;
        return this;
    }

    public CitizenIdentityTokenBuilder setCprNumberAttribute(String cprNumber) {
        this.cprNumber = cprNumber;
        return this;
    }

    public CitizenIdentityTokenBuilder setSubjectNameID(String subjectNameID) {
        this.subjectNameID = subjectNameID;
        return this;
    }

    public CitizenIdentityTokenBuilder setSubjectNameIDFormat(String subjectNameIDFormat) {
        this.subjectNameIDFormat = subjectNameIDFormat;
        return this;
    }

    public CitizenIdentityTokenBuilder setRecipientURL(String recipientURL) {
        this.recipientURL = recipientURL;
        return this;
    }

    public CitizenIdentityTokenBuilder setDeliveryNotOnOrAfter(Date deliveryNotOnOrAfter) {
        this.deliveryNotOnOrAfter = deliveryNotOnOrAfter;
        return this;
    }

    public CitizenIdentityTokenBuilder setHolderOfKeyCertificate(X509Certificate holderOfKeyCertificate) {
        this.holderOfKeyCertificate = holderOfKeyCertificate;
        return this;
    }

    public CitizenIdentityTokenBuilder setSigningVault(CredentialVault signingVault) {
        this.signingVault = signingVault;
        return this;
    }

    @Override
    protected void validateBeforeBuild() {
        super.validateBeforeBuild();
        validate("notBefore", notBefore);
        validate("audienceRestriction", audienceRestriction);
        validate("notOnOrAfter", notOnOrAfter);
        validate("cpr", cprNumber);
        validate("subjectNameID", subjectNameID);
        validate("subjectNameIDFormat", subjectNameIDFormat);
        validate("holderOfKeyCertificate", holderOfKeyCertificate);
        validate("deliveryNotOnOrAfter", deliveryNotOnOrAfter);
        validate("recipientURL", recipientURL);
        validate("signingVault", signingVault);

        if(!notBefore.before(notOnOrAfter)) {
            throw new ModelException("notBefore is after notOnOrAfter");
        }
    }

    @Override
    public IdentityToken build() throws ModelException {
        Document document = createDocument();
        signAssertion(document);

        return new IdentityToken((Element)document.getFirstChild());
    }

    @Override
    protected final void appendToRoot(Document doc, Element root) {
        super.appendToRoot(doc, root);
        subjectNode = createSubject();
        root.appendChild(subjectNode);
        root.appendChild(createConditions());
        root.appendChild(createAttributeStatement(doc));
    }

    protected Node createSubject() {
        Element subjectElm = createElement(SAMLTags.subject);

        Element nameIdElm = createElement(SAMLTags.nameID);
        nameIdElm.setAttributeNS(null, SAMLAttributes.FORMAT, subjectNameIDFormat);
        nameIdElm.setTextContent(subjectNameID);
        subjectElm.appendChild(nameIdElm);

        Element subjectConfirmationElm = createElement(SAMLTags.subjectConfirmation);
        subjectConfirmationElm.setAttributeNS(null, SAMLAttributes.METHOD, SAMLValues.CONFIRMATION_METHOD_HOLDER_OF_KEY);
        subjectElm.appendChild(subjectConfirmationElm);

        Element subjectConfirmationDataElm = createElement(SAMLTags.subjectConfirmationData);
        subjectConfirmationDataElm.setAttributeNS(null, SAMLAttributes.RECIPIENT, recipientURL);
        subjectConfirmationDataElm.setAttributeNS(null, SAMLAttributes.NOT_ON_OR_AFTER, XmlUtil.getDateFormat(true).format(deliveryNotOnOrAfter));
        subjectConfirmationElm.appendChild(subjectConfirmationDataElm);

        Element keyInfoElm = createElement(DSTags.keyInfo);
        Element x509DataElm = createElement(DSTags.x509Data);
        keyInfoElm.appendChild(x509DataElm);
        Element x509CertificateElm = createElement(DSTags.x509Certificate);
        x509DataElm.appendChild(x509CertificateElm);
        try {
            String encodedCert = XmlUtil.toBase64(holderOfKeyCertificate.getEncoded());
            x509CertificateElm.setTextContent(encodedCert);
        } catch (CertificateEncodingException e) {
            throw new ModelException("Unable to encode certificate", e);
        }
        subjectConfirmationDataElm.appendChild(keyInfoElm);



        return subjectElm;
    }

    private Element createAttributeStatement(Document doc) {
        Element attributeStatementElm = createElement(SAMLTags.attributeStatement);
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.SPEC_VERSION, null, SAMLValues.DK_SPEC_VERSION));
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.ASSURANCE_LEVEL, null, SAMLValues.ASSURANCELEVEL_3));
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.CPR_NUMBER, null, cprNumber));
        return attributeStatementElm;
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

        SignatureUtil.sign(SignatureProviderFactory.fromCredentialVault(signingVault), document, signatureConfiguration);
    }

}
