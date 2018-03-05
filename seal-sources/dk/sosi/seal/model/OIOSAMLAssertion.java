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
import dk.sosi.seal.modelbuilders.IDCardModelBuilder;
import dk.sosi.seal.modelbuilders.ModelBuildException;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class OIOSAMLAssertion extends AbstractOIOSAMLToken {

    private static Schema schema;

    /*pp*/ OIOSAMLAssertion(Element element, boolean validate) {
        super(element);
        if (validate) {
            validateElement(element);
            validateSchema(element);
        }
    }

    public OIOSAMLAssertion(Element element) {
        this(element, true);
    }

    private void validateElement(Element element) {
        if (! (NameSpaces.SAML2ASSERTION_SCHEMA.equals(element.getNamespaceURI())
                && SAMLTags.ASSERTION.equals(element.getLocalName()))) {
            throw new IllegalArgumentException("Element is not a SAML assertion");
        }
    }

    private void validateSchema(Node node) {
        try {
            final Validator validator = getSchema().newValidator();
            validator.validate(new DOMSource(node));
        } catch (SAXException e) {
            throw new ModelBuildException("Error validating OIOSAMLAssertion", e);
        } catch (IOException e) {
            throw new ModelBuildException("Error validating OIOSAMLAssertion", e);
        }
    }

    private static synchronized Schema getSchema() throws SAXException {
        if (schema == null) {
            schema = SchemaUtil.loadSchema("/oiosaml/standard-saml.xsd");
        }
        return schema;
    }

    /**
     * Checks the signature on the <code>OIOSAMLAssertion</code>.
     *
     * @param vault
     *            The CredentialVault containing trusted certificates used to check trust for the <code>OIOSAMLAssertion</code>.
     *
     * @throws dk.sosi.seal.model.ModelException
     *             Thrown if the signature on the <code>OIOSAMLAssertion</code> is invalid.
     */
    public void validateSignatureAndTrust(CredentialVault vault) {
        List<Element> signatureElements = XmlUtil.getChildElementsNS(dom, NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE);
        if (signatureElements.size() == 0) {
            throw new ModelException("OIOSAMLAssertion is not signed");
        }
        Element signatureElement = signatureElements.get(0);
        List<Element> referencedSignedElements = SignatureUtil.dereferenceSignedElements(signatureElement);
        if (! referencedSignedElements.contains(dom)) {
            throw new ModelException("OIOSAMLAssertion element is not referenced by contained signature");
        }
        if(! SignatureUtil.validate(signatureElement, null, vault, true)) {
            throw new ModelException("Signature on OIOSAMLAssertion is invalid");
        }
    }


    /**
     * Extract the <code>dk:gov:saml:attribute:RidNumberIdentifier</code> value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
     *         Name="dk:gov:saml:attribute:RidNumberIdentifier"&gt;
     *         &lt;saml:AttributeValue xsi:type="xs:string"&gt;1118061020235&lt;/saml:AttributeValue&gt;
     *       &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:gov:saml:attribute:RidNumberIdentifier</code> tag.
     */
    public String getRidNumberIdentifier() {
        return getAttribute(OIOSAMLAttributes.RID_NUMBER);
    }

    public String getCertificateIssuer() {
        return getAttribute(OIOSAMLAttributes.CERTIFICATE_ISSUER);
    }

    /**
     * Extract the <code>urn:oid:1.3.6.1.4.1.1466.115.121.1.8</code>/userCertificate value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
     *         Name="urn:oid:1.3.6.1.4.1.1466.115.121.1.8"
     *         FriendlyName="userCertificate"&gt;
     *         &lt;saml:AttributeValue xsi:type="xs:string"&gt;MIIB5DCCAU0CBAJQodoZIhvcNAQ....&lt;/saml:AttributeValue&gt;
     *       &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>urn:oid:1.3.6.1.4.1.1466.115.121.1.8</code>/userCertificate tag.
     */
    public X509Certificate getUserCertificate() {
        String certString = getAttribute(OIOSAMLAttributes.USER_CERTIFICATE);
        if (certString == null) {
            return null;
        } else {
            return CertificateParser.asCertificate(XmlUtil.fromBase64(certString));
        }
    }

    public String getRecipient() {
        Element subjectConfirmationData = getTag(SAMLTags.assertion, SAMLTags.subject, SAMLTags.subjectConfirmation, SAMLTags.subjectConfirmationData);
        if (subjectConfirmationData == null) {
            return null;
        }
        return subjectConfirmationData.getAttribute(SAMLAttributes.RECIPIENT);
    }

    public Date getDeliveryNotOnOrAfter() {
        Element subjectConfirmationData = getTag(SAMLTags.assertion, SAMLTags.subject, SAMLTags.subjectConfirmation, SAMLTags.subjectConfirmationData);
        if (subjectConfirmationData == null) {
            return null;
        }
        return convertToDate(subjectConfirmationData, SAMLAttributes.NOT_ON_OR_AFTER);
    }

    public String getSubjectNameID() {
        Element nameID = getTag(SAMLTags.assertion, SAMLTags.subject, SAMLTags.nameID);
        if (nameID == null) {
            return null;
        }
        return nameID.getTextContent().trim();
    }

    public String getSubjectNameIDFormat() {
        Element nameID = getTag(SAMLTags.assertion, SAMLTags.subject, SAMLTags.nameID);
        if (nameID == null) {
            return null;
        }
        return nameID.getAttribute(SAMLAttributes.FORMAT);
    }

    public boolean isYouthCertificate() {
        return Boolean.parseBoolean(getAttribute(OIOSAMLAttributes.IS_YOUTH_CERT));
    }

    public String getCertificateSerial() {
        return getAttribute(OIOSAMLAttributes.CERTIFICATE_SERIAL);
    }

    public String getUID() {
        return getAttribute(OIOSAMLAttributes.UID);
    }

    public UserIDCard getUserIDCard() {
        Element discoveryEPR = getAttributeElement(OIOSAMLAttributes.DISCOVERY_EPR);
        Element metadata = getTag(discoveryEPR, SAMLTags.attribute, SAMLTags.attributeValue, WSATags.endpointReference, WSATags.metadata);
        Element serviceType = getTag(metadata, WSATags.metadata, LibertyDiscoveryTags.serviceType);
        if (serviceType != null && LibertyValues.SOSI_URN.equals(serviceType.getTextContent())) {
            Element idCardElm = getTag(metadata, WSATags.metadata, LibertyDiscoveryTags.securityContext, LibertySecurityTags.token, SAMLTags.assertion);
            return (UserIDCard) new IDCardModelBuilder().buildModel(idCardElm);
        } else {
            return null;
        }
    }

    /**
     * Gets the signing certificate
     *
     * @return Returns the certificate contained in assertions XML signature or <code>null</code> if the assertion was not signed
     */
    public X509Certificate getSigningCertificate() {
        Element certificateElm = getTag(SAMLTags.assertion, DSTags.signature, DSTags.keyInfo, DSTags.x509Data, DSTags.x509Certificate);
        if (certificateElm == null) {
            return null;
        } else {
            return CertificateParser.asCertificate(XmlUtil.fromBase64(certificateElm.getTextContent()));
        }
    }

}
