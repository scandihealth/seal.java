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
import dk.sosi.seal.model.dombuilders.AbstractOIOSAMLTokenBuilder;
import dk.sosi.seal.pki.CertificateInfo;
import dk.sosi.seal.pki.DistinguishedName;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.Date;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOSAMLAssertionBuilder extends AbstractOIOSAMLTokenBuilder<OIOSAMLAssertionBuilder, OIOSAMLAssertion>{

    private CertificateInfo certificateInfo;
    private String recipientURL;
    private Date deliveryNotOnOrAfter;
    private String ridNumber;
    private boolean includeIDCardAsBootstrapToken;

    public OIOSAMLAssertionBuilder() {
        extractCprNumber = true;
        extractCvrNumberIdentifier = true;
        extractOrganizationName = true;
    }

    public OIOSAMLAssertionBuilder setRecipientURL(String recipientURL) {
        this.recipientURL = recipientURL;
        return this;
    }

    public OIOSAMLAssertionBuilder setDeliveryNotOnOrAfter(Date deliveryNotOnOrAfter) {
        this.deliveryNotOnOrAfter = deliveryNotOnOrAfter;
        return this;
    }

    public OIOSAMLAssertionBuilder includeIDCardAsBootstrapToken() {
        this.includeIDCardAsBootstrapToken = true;
        return this;
    }

    @Override
    protected void validateBeforeBuild() {
        super.validateBeforeBuild();
        if (!CertificateInfo.isProbableCertificateInfoString(userIdCard.getAlternativeIdentifier())) {
            throw new ModelException("Subject NameID is not in CertificateInfo format");
        }
        certificateInfo = CertificateInfo.fromString(userIdCard.getAlternativeIdentifier());
        validateCertificateInfo();
        ridNumber = extractRidNumber(certificateInfo.getSubjectDN().getSubjectSerialNumber());
        validate("recipientURL", recipientURL);
        validate("deliveryNotOnOrAfter", deliveryNotOnOrAfter);
    }

    @Override
    public OIOSAMLAssertion build() throws ModelException {
        Document document = createDocument();
        signAssertion(document);

        return new OIOSAMLAssertion((Element)document.getFirstChild(), false);
    }

    @Override
    protected void addRootAttributes(Element root) {
        super.addRootAttributes(root);
        if (includeIDCardAsBootstrapToken) {
            addNS(root, NameSpaces.NS_WSA, NameSpaces.WSA_1_0_SCHEMA);
            addNS(root, NameSpaces.NS_LIB_DISCO, NameSpaces.LIBERTY_DISCOVERY_SCHEMA);
            addNS(root, NameSpaces.NS_LIB_SEC, NameSpaces.LIBERTY_SECURITY_SCHEMA);
        }
    }

    @Override
    protected Node createSubject() {
        Element subjectElm = createElement(SAMLTags.subject);

        Element nameIdElm = createElement(SAMLTags.nameID);
        nameIdElm.setAttributeNS(null, SAMLAttributes.FORMAT, SAMLValues.NAMEID_FORMAT_X509_SUBJECT_NAME);
        nameIdElm.setTextContent(formatDN(certificateInfo.getSubjectDN(), true));
        subjectElm.appendChild(nameIdElm);

        Element subjectConfirmationElm = createElement(SAMLTags.subjectConfirmation);
        subjectConfirmationElm.setAttributeNS(null, SAMLAttributes.METHOD, SAMLValues.CONFIRMATION_METHOD_BEARER);
        subjectElm.appendChild(subjectConfirmationElm);

        Element subjectConfirmationDataElm = createElement(SAMLTags.subjectConfirmationData);
        subjectConfirmationDataElm.setAttributeNS(null, SAMLAttributes.RECIPIENT, recipientURL);
        subjectConfirmationDataElm.setAttributeNS(null, SAMLAttributes.NOT_ON_OR_AFTER, XmlUtil.getDateFormat(true).format(deliveryNotOnOrAfter));
        subjectConfirmationElm.appendChild(subjectConfirmationDataElm);

        return subjectElm;
    }

    @Override
    protected void addExtraAttributes(Document doc, Element attributeStatementElm) {
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.CERTIFICATE_ISSUER, null, formatDN(certificateInfo.getIssuerDN(), false)));
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.UID, OIOSAMLAttributes.UID_FRIENDLY, certificateInfo.getSubjectDN().getSubjectSerialNumber()));
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.RID_NUMBER, null, ridNumber));
        String serial = certificateInfo.getCertificateSerialNumber().toString(16);
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.CERTIFICATE_SERIAL, OIOSAMLAttributes.CERTIFICATE_SERIAL_FRIENDLY, serial));
        attributeStatementElm.appendChild(createAttributeElement(OIOSAMLAttributes.IS_YOUTH_CERT, null, Boolean.FALSE.toString()));
        if (includeIDCardAsBootstrapToken) {
            addIDCardAsBootstrapToken(doc, attributeStatementElm);
        }
    }

    private void addIDCardAsBootstrapToken(Document doc, Element attributeStatementElm) {

        Element attributeElm = createElement(SAMLTags.attribute);
        attributeElm.setAttributeNS(null, SAMLAttributes.NAME, OIOSAMLAttributes.DISCOVERY_EPR);
        attributeElm.setAttributeNS(null, SAMLAttributes.NAME_FORMAT, SAMLValues.NAME_FORMAT_URI);
        attributeStatementElm.appendChild(attributeElm);

        Element attributeValue = createElement(SAMLTags.attributeValue);
        attributeElm.appendChild(attributeValue);

        Element endpointReferenceElm = createElement(WSATags.endpointReference);
        attributeValue.appendChild(endpointReferenceElm);

        Element addressElm = createElement(WSATags.address);
        addressElm.setTextContent(LibertyValues.SOSI_STS_URI);
        endpointReferenceElm.appendChild(addressElm);

        Element metadataElm = createElement(WSATags.metadata);
        endpointReferenceElm.appendChild(metadataElm);

        Element abstractElm = createElement(LibertyDiscoveryTags._abstract);
        abstractElm.setTextContent("A SOSI idcard");
        metadataElm.appendChild(abstractElm);

        Element serviceTypeElm = createElement(LibertyDiscoveryTags.serviceType);
        serviceTypeElm.setTextContent(LibertyValues.SOSI_URN);
        metadataElm.appendChild(serviceTypeElm);

        Element providerIDElm = createElement(LibertyDiscoveryTags.providerID);
        providerIDElm.setTextContent(LibertyValues.SOSI_STS_URI);
        metadataElm.appendChild(providerIDElm);

        Element securityContextElm = createElement(LibertyDiscoveryTags.securityContext);
        metadataElm.appendChild(securityContextElm);

        Element securityMechID = createElement(LibertyDiscoveryTags.securityMechID);
        securityMechID.setTextContent(LibertyValues.SAML_SECURITY_MECH_ID);
        securityContextElm.appendChild(securityMechID);

        Element tokenElm = createElement(LibertySecurityTags.token);
        tokenElm.setAttributeNS(null, LibertyAttributes.USAGE, LibertyValues.TOKEN_USAGE_SECURITY_TOKEN);
        securityContextElm.appendChild(tokenElm);

        Element idCardElm = userIdCard.serialize2DOMDocument(null, doc);
        tokenElm.appendChild(idCardElm);
    }

    @Override
    protected void addExtraAuthnAttributes(Element authnStatementElm) {
        // SessionIndex is mandatory in OIOSAML (to support per session logout), but is meaningless
        // for STS issued assertions
        authnStatementElm.setAttributeNS(null, SAMLAttributes.SESSION_INDEX, assertionID);
    }

    private void validateCertificateInfo() {
        validateDN(certificateInfo.getSubjectDN(), "SubjectDN", true);
        validateDN(certificateInfo.getIssuerDN(), "IssuerDN", false);
    }

    private void validateDN(DistinguishedName name, String identifier, boolean requireSerial) {
        validate("Country ('C') in " + identifier, name.getCountry());
        validate("Organization ('O') in " + identifier, name.getOrganization());
        validate("Common Name ('CN') in " + identifier, name.getCommonName());
        if (requireSerial) {
            validate("Subject Serial Number ('SERIAL') in " + identifier, name.getSubjectSerialNumber());
        }
    }

    private String formatDN(DistinguishedName name, boolean requireSerial) {
        StringBuilder builder = new StringBuilder("C=");
        builder.append(name.getCountry());
        builder.append(",O=");
        builder.append(name.getOrganization());
        builder.append(",CN=");
        builder.append(name.getCommonName());
        if (requireSerial) {
            builder.append(",Serial=");
            builder.append(name.getSubjectSerialNumber());
        }
        return builder.toString();
    }

    private String extractRidNumber(String subjectSerialNumber) {
        String ridIdentifier = "RID:";
        int index = subjectSerialNumber.indexOf(ridIdentifier);
        if (index == -1) {
            throw new ModelException("Could not extract RID number from subject serial number: '" + subjectSerialNumber + "'");
        } else {
            return subjectSerialNumber.substring(index + ridIdentifier.length());
        }
    }

}
