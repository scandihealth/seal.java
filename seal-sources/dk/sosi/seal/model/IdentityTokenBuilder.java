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

import dk.sosi.seal.model.constants.DSTags;
import dk.sosi.seal.model.constants.SAMLAttributes;
import dk.sosi.seal.model.constants.SAMLTags;
import dk.sosi.seal.model.constants.SAMLValues;
import dk.sosi.seal.model.dombuilders.AbstractOIOSAMLTokenBuilder;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.vault.CredentialVault;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.UnsupportedEncodingException;

/**
 * Builder class used for constructing <code>IdentityToken</code> objects.<br />
 * An <code>IdentityToken</code> is generated using the following mandatory values:
 * <ul>
 * <li>Audience restriction.
 * <li>Key name.
 * <li>Not before.
 * <li>Not on or after.
 * <li><code>UserIDCard</code>.
 * </ul>
 * <br />
 * All operations related to constructing, wrapping, etc. of the <code>IdentityToken</code> should be done through the <code>IDWSHFactory</code>.
 * 
 * @author ads
 * @since 2.1
 */
public final class IdentityTokenBuilder extends AbstractOIOSAMLTokenBuilder<IdentityTokenBuilder, IdentityToken> {

    private static final String KEY_ID = "SigningKey";

    /**
     * Constructs an <code>IdentityToken</code> based on the contents of a URL parameter.
     *
     *
     * @param urlParameterValue
     *            <code>String</code> representation of an <code>IdentityToken</code> taken from a URL parameter.
     * @param federation The federation to chect trust against
     * @return The constructed <code>IdentityToken</code>.
     */
    public static IdentityToken constructFromURLString(String urlParameterValue, Federation federation) {
        try {
            return new IdentityToken(urlParameterValue, federation);
        } catch (UnsupportedEncodingException e) {
            throw new ModelException("Cannot construct IdentityToken from serialized form", e);
        }
    }

    private boolean certAsReference;

    /**
     * Default constructor for the <code>IdentityTokenBuilder</code> class.
     * 
     * @param credentialVault
     *            Required <code>CredentialVault</code> used for signing the generated DOM inside the <code>IdentityToken</code>.
     */
    public IdentityTokenBuilder(CredentialVault credentialVault) {
        setSigningVault(credentialVault);
    }

    /**
     * Build the final identity token.<br />
     * Before the <code>Document</code> is generated all attributes will be validated.<br />
     * <br />
     * An <code>IdentityToken</code> is generated through the following steps:
     * <ol>
     * <li>The DOM representation of the <code>IdentityToken</code> is generated.
     * <li>The DOM is then signed used the <code>CredentialVault</code> supplied to the constructor of the <code>IdentityTokenBuilder</code>.
     * <li>The <code>KeyInfo</code> part is then added to the signed document
     * <li>Finally a new <code>IdentityToken</code> object is created based on the generated and signed DOM.
     * </ol>
     * <br />
     * An <code>IdentityToken</code> is generated each time the method is called. Calling this method multiple times will therefore return multiple objects.
     * 
     * @return DOM representation of the Identity token.
     * @throws ModelException
     *             Thrown if the builder finds a validation problem.
     */
    public final IdentityToken build() throws ModelException {
        Document document = createDocument();
        signAssertion(document);
        return new IdentityToken((Element)document.getFirstChild());
    }

    /**
     * <b>Optional</b>: Include only a reference to the certificate that can validate this identity token instead of the certificate itself.<br />
     * Example:
     * 
     * <pre>
     *  &lt;ds:KeyInfo Id="SigningKey"&gt;
     *      &lt;ds:KeyName&gt;OCES2,CVR:55832218-UID:1163447368627,1077391241&lt;/ds:KeyName&gt;
     *  &lt;/ds:KeyInfo&gt;
     * </pre>
     * 
     * @return The <code>IdentityTokenBuilder</code> instance.
     */
    public IdentityTokenBuilder requireCertificateAsReference() {
        this.certAsReference = true;
        return this;
    }

    /**
     * <b>Optional</b>: Instructs the <code>IdentityTokenBuilder</code> to extract the cpr number from the <code>IDCard</code>.<br />
     * Example:
     * 
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:gov:saml:attribute:CprNumberIdentifier"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;1111111118&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     * 
     * @return The <code>IdentityTokenBuilder</code> instance.
     */
    public IdentityTokenBuilder requireCprNumber() {
        this.extractCprNumber = true;
        return this;
    }

    /**
     * <b>Optional</b>: Instructs the <code>IdentityTokenBuilder</code> to extract the CVR number from the <code>CareProvider</code> associated with the <code>IDCard</code>.<br />
     * Example:
     * 
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:gov:saml:attribute:CvrNumberIdentifier"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;20688092&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     * 
     * @return The <code>IdentityTokenBuilder</code> instance.
     */
    public IdentityTokenBuilder requireCvrNumberIdentifier() {
        this.extractCvrNumberIdentifier = true;
        return this;
    }

    /**
     * <b>Optional</b>: Instructs the <code>IdentityTokenBuilder</code> to extract the organization name from the <code>CareProvider</code> associated with the <code>IDCard</code>.<br />
     * Example:
     * 
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="urn:oid:2.5.4.10" FriendlyName="organizationName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Lægehuset på bakken&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     * 
     * @return The <code>IdentityTokenBuilder</code> instance.
     */
    public IdentityTokenBuilder requireOrganizationName() {
        this.extractOrganizationName = true;
        return this;
    }

    /**
     * <b>Optional</b>: Instructs the <code>IdentityTokenBuilder</code> to extract the ITSystem name from the <code>IDCard</code>.<br />
     * Example:
     * 
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:healthcare:saml:attribute:ITSystemName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Harmoni/EMS&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     * 
     * @return The <code>IdentityTokenBuilder</code> instance.
     */
    public IdentityTokenBuilder requireITSystemName() {
        this.extractITSystemName = true;
        return this;
    }

    /**
     * <b>Optional</b>: Instructs the <code>IdentityTokenBuilder</code> to extract the UserAuthorizationCode from the <code>IDCard</code>.<br />
     * Example:
     * 
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:healthcare:saml:attribute:UserAuthorizationCode"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;004PT&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     * 
     * @return The <code>IdentityTokenBuilder</code> instance.
     */
    public IdentityTokenBuilder requireUserAuthorizationCode() {
        this.extractUserAuthorizationCode = true;
        return this;
    }

    /**
     * <b>Optional</b>: Instructs the <code>IdentityTokenBuilder</code> to extract the UserEducationCode from the <code>IDCard</code>.<br />
     * Example:
     * 
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:healthcare:saml:attribute:UserEducationCode"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;7170&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     * 
     * @return The <code>IdentityTokenBuilder</code> instance.
     */
    public IdentityTokenBuilder requireUserEducationCode() {
        this.extractUserEducationCode = true;
        return this;
    }

    @Override
    protected void addExtraSignatureConfiguration(SignatureConfiguration signatureConfiguration) {
        signatureConfiguration.setAddCertificateAsReference(certAsReference);
        signatureConfiguration.setKeyInfoId(KEY_ID);
    }

    @Override
    protected Node createSubject() {
        Element subjectElm = createElement(SAMLTags.subject);

        Element nameIdElm = createElement(SAMLTags.nameID);
        nameIdElm.setAttributeNS(null, SAMLAttributes.FORMAT, SAMLValues.NAMEID_FORMAT_UNSPECIFIED);
        if(userIdCard.getAlternativeIdentifier() != null) {
            nameIdElm.setTextContent(userIdCard.getAlternativeIdentifier());
        } else {
            nameIdElm.setTextContent(userIdCard.getUserInfo().getCPR());
        }
        subjectElm.appendChild(nameIdElm);

        Element subjectConfirmationElm = createElement(SAMLTags.subjectConfirmation);
        subjectConfirmationElm.setAttributeNS(null, SAMLAttributes.METHOD, SAMLValues.CONFIRMATION_METHOD_HOLDER_OF_KEY);

        Element subjectConfirmationDataElm = createElement(SAMLTags.subjectConfirmationData);
        Element keyInfoElm = createElement(DSTags.keyInfo);
        Element keyNameElm = createElement(DSTags.keyName);
        keyNameElm.setTextContent(KEY_ID);

        keyInfoElm.appendChild(keyNameElm);
        subjectConfirmationDataElm.appendChild(keyInfoElm);
        subjectConfirmationElm.appendChild(subjectConfirmationDataElm);

        subjectElm.appendChild(subjectConfirmationElm);
        return subjectElm;
    }
}