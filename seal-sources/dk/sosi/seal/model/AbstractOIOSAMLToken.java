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

import dk.sosi.seal.model.constants.OIOSAMLAttributes;
import dk.sosi.seal.model.constants.SAMLAttributes;
import dk.sosi.seal.model.constants.SAMLTags;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Element;

import java.text.DateFormat;
import java.util.Date;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public abstract class AbstractOIOSAMLToken extends AbstractSAMLToken {

    public AbstractOIOSAMLToken(Element dom) {
        super(dom);
    }

    /**
     * Extract the <code>urn:oid:2.5.4.3</code>/CommonName value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="urn:oid:2.5.4.3"
     *       FriendlyName="CommonName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Jens Sundbye Poulsen&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>urn:oid:2.5.4.3</code>/CommonName tag.
     */
    public String getCommonName() {
        Element commonNameElm = getAttributeElement(OIOSAMLAttributes.COMMON_NAME);
        if(commonNameElm == null) {
            throw new ModelException("Mandatory 'commonName' SAML attribute (urn:oid:2.5.4.3) is missing");
        }
        return commonNameElm.getTextContent().trim();
    }

    /**
     * Extract the <code>dk:gov:saml:attribute:CprNumberIdentifier</code> value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
     *       Name="dk:gov:saml:attribute:CprNumberIdentifier"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;2702681273&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:gov:saml:attribute:CprNumberIdentifier</code> tag.
     */
    public String getCpr() {
        return getAttribute(OIOSAMLAttributes.CPR_NUMBER);
    }

    /**
     * Extract the <code>dk:gov:saml:attribute:CvrNumberIdentifier</code> value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
     *         Name="dk:gov:saml:attribute:CvrNumberIdentifier"&gt;
     *         &lt;saml:AttributeValue xsi:type="xs:string"&gt;20688092&lt;/saml:AttributeValue&gt;
     *       &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:gov:saml:attribute:CvrNumberIdentifier</code> tag.
     */
    public String getCvrNumberIdentifier() {
        return getAttribute(OIOSAMLAttributes.CVR_NUMBER);
    }

    /**
     * Extract the <code>urn:oid:0.9.2342.19200300.100.1.3</code>/email value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
     *       Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="email"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;jens@email.dk&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>urn:oid:0.9.2342.19200300.100.1.3</code>/email tag.
     */
    public String getEmail() {
        Element emailElm = getAttributeElement(OIOSAMLAttributes.EMAIL);
        if(emailElm == null) {
            throw new ModelException("Mandatory 'email' SAML attribute (urn:oid:0.9.2342.19200300.100.1.3) is missing");
        }
        return emailElm.getTextContent().trim();
    }

    /**
     * Extract the <code>saml:Conditions#NotBefore</code> value from the DOM.<br />
     *
     * <pre>
     *   &lt;saml:Conditions NotBefore="2011-07-23T15:32:12Z" ... &gt;
     *      ...
     *   &lt;/saml:Conditions&gt;
     * </pre>
     *
     * @return The value of the <code>saml:Conditions#NotBefore</code> tag.
     */
    public Date getNotBefore() throws ModelException {
        Element ac = getTag(SAMLTags.assertion, SAMLTags.conditions);
        return convertToDate(ac, SAMLAttributes.NOT_BEFORE);
    }

    /**
     * Extract the <code>saml:Conditions#NotOnOrAfter</code> value from the DOM.<br />
     *
     * <pre>
     *   &lt;saml:Conditions ... NotOnOrAfter="2011-07-23T15:37:12Z" &gt;
     *      ...
     *   &lt;/saml:Conditions&gt;
     * </pre>
     *
     * @return The value of the <code>saml:Conditions#NotOnOrAfter</code> tag.
     */
    public Date getNotOnOrAfter() {
        Element ac = getTag(SAMLTags.assertion, SAMLTags.conditions);
        return convertToDate(ac, SAMLAttributes.NOT_ON_OR_AFTER);
    }

    /**
     * Extract the <code>urn:oid:2.5.4.10</code>/organizationName value from the token.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="urn:oid:2.5.4.10"
     *       FriendlyName="organizationName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Lægehuset på bakken&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>urn:oid:2.5.4.10</code>/organizationName tag.
     */
    public String getOrganizationName() {
        return getAttribute(OIOSAMLAttributes.ORGANIZATION_NAME);
    }

    /**
     * Extract the <code>urn:oid:2.5.4.4</code>/surName value from the token.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="urn:oid:2.5.4.4"
     *       FriendlyName="surName"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;Poulsen&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>urn:oid:2.5.4.4</code>/surName tag.
     */
    public String getSurName() {
        Element surNameElm = getAttributeElement(OIOSAMLAttributes.SURNAME);
        if(surNameElm == null) {
            throw new ModelException("Mandatory 'surName' SAML attribute (urn:oid:2.5.4.4) is missing");
        }
        return surNameElm.getTextContent().trim();
    }

    /**
     * Extract the <code>dk:gov:saml:attribute:AssuranceLevel</code> value from the token.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:gov:saml:attribute:AssuranceLevel"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;3&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:gov:saml:attribute:AssuranceLevel</code> tag.
     */
    public String getAssuranceLevel() {
        Element assuranceLevelElm = getAttributeElement(OIOSAMLAttributes.ASSURANCE_LEVEL);
        if(assuranceLevelElm == null) {
            throw new ModelException("Mandatory 'assuranceLevel' SAML attribute (dk:gov:saml:attribute:AssuranceLevel) is missing");
        }
        return assuranceLevelElm.getTextContent().trim();
    }

    /**
     * Extract the <code>dk:gov:saml:attribute:SpecVer</code> value from the DOM.<br />
     *
     * <pre>
     *     &lt;saml:Attribute NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" Name="dk:gov:saml:attribute:SpecVer"&gt;
     *       &lt;saml:AttributeValue xsi:type="xs:string"&gt;DK-SAML-2.0&lt;/saml:AttributeValue&gt;
     *     &lt;/saml:Attribute&gt;
     * </pre>
     *
     * @return The value of the <code>dk:gov:saml:attribute:SpecVer</code> tag.
     */
    public String getSpecVersion() {
        Element specVersionElm = getAttributeElement(OIOSAMLAttributes.SPEC_VERSION);
        if(specVersionElm == null) {
            throw new ModelException("Mandatory 'specVersion' SAML attribute (dk:gov:saml:attribute:SpecVer) is missing");
        }
        return specVersionElm.getTextContent().trim();
    }

    /**
     * Extract the <code>saml:AudienceRestriction</code> value from the DOM.<br />
     *
     * <pre>
     *   &lt;saml:Conditions ... &gt;
     *      &lt;saml:AudienceRestriction&gt;http://fmk-online.dk&lt;/saml:AudienceRestriction&gt;
     *   &lt;/saml:Conditions&gt;
     * </pre>
     *
     * @return The value of the <code>saml:AudienceRestriction</code> tag.
     */
    public String getAudienceRestriction() {
        Element ac = getTag(SAMLTags.assertion, SAMLTags.conditions, SAMLTags.audienceRestriction);
        if (ac == null) {
            return null;
        }
        return ac.getTextContent().trim();
    }

    /**
     * Extract the <code>AuthnInstant</code> value from the DOM, that is the time the user originally authenticated herself.<br />
     *
     * <pre>
     *       &lt;saml:AuthnStatement AuthnInstant="2011-07-23T11:42:52Z"&gt;
     *          &lt;saml:AuthnContext&gt;
     *              &lt;saml:AuthnContextClassRef&gt;urn:oasis:names:tc:SAML:2.0:ac:classes:X509&lt;/saml:AuthnContextClassRef&gt;
     *          &lt;/saml:AuthnContext&gt;
     *       &lt;/saml:AuthnStatement&gt;
     *
     * @return The value of the <code>AuthnInstant</code> attribute.
     */
    public Date getUserAuthenticationInstant() {
        final Element auth = getTag(SAMLTags.assertion, SAMLTags.authnStatement);
        return convertToDate(auth, SAMLAttributes.AUTHN_INSTANT);
    }

    /**
     * Invoke this method to verify the validity of the <code>AbstractOIOSamlToken</code> against the {@link #getNotBefore()} and {@link #getNotOnOrAfter()} values.<br />
     *
     * @throws dk.sosi.seal.model.ModelException
     *             Thrown if the <code>AbstractOIOSamlToken</code> is invalid.
     */
    public void validateTimestamp() throws ModelException {
        validateTimestamp(0);
    }

    /**
     * Invoke this method to verify the validity of the <code>AbstractOIOSamlToken</code> against the {@link #getNotBefore()} and {@link #getNotOnOrAfter()} values.<br />
     *
     * @param allowedDriftInSeconds the amount of clock drift to allow in milliseconds
     *
     * @throws dk.sosi.seal.model.ModelException
     *             Thrown if the <code>AbstractOIOSamlToken</code> is invalid.
     */
    public void validateTimestamp(long allowedDriftInSeconds) throws ModelException {
        if (allowedDriftInSeconds < 0) throw new IllegalArgumentException("'allowedDriftInSeconds' must not be negative!");
        Date now = new Date();
        DateFormat format = XmlUtil.getDateFormat(true);

        if (new Date(now.getTime() + allowedDriftInSeconds * 1000).before(getNotBefore())) {
            throw new ModelException("OIOSAML token is not valid yet - now: " + format.format(now) +
                    ". OIOSAML token validity start: " + format.format(getNotBefore()) + ". Allowed clock drift: " + allowedDriftInSeconds + " seconds");
        }
        if (!new Date(now.getTime() - allowedDriftInSeconds * 1000).before(getNotOnOrAfter())) {
            throw new ModelException("OIOSAML token no longer valid - now: "  + format.format(now) +
                    ". OIOSAML token validity end: "  + format.format(getNotOnOrAfter()) + ". Allowed clock drift: " + allowedDriftInSeconds + " seconds");
        }

    }

}