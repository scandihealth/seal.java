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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/dombuilders/IDCardDOMBuilder.java $
 * $Id: IDCardDOMBuilder.java 20767 2014-12-10 15:12:04Z ChristianGasser $
 */
package dk.sosi.seal.model.dombuilders;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.*;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.xml.XmlUtil;
import org.apache.xml.security.utils.IdResolver;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Converts an <code>IDCard</code> model instance into a DOM element. <p/>
 * This DOM builder will automatically adds a digital signature to the DOM if
 * the idcard.signatureType is "VOCES". <p/> <b>This class should only be
 * accessed through model classes</b>
 * </p>
 *
 * @author Jan Riis
 * @author $Author: ChristianGasser $
 * @since 1.0
 */
public class IDCardDOMBuilder {

	private static final String SAML_MAJOR_VERSION = "2";
	private static final String SAML_MINOR_VERSION = "0";
	private static final String HOLDER_OF_KEY = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";

	private final IDCard idCard;
	private final Document document;
	private final SAMLUtil samlUtil = new SAMLUtil();

    private final SOSIFactory factory;
	/**
	 * Constructs an <code>IDCardDOMBuilder</code> instance.
	 * @param factory
	 */
	public IDCardDOMBuilder(SOSIFactory factory, Document domDocument, IDCard idCard) {

		super();
		this.idCard = idCard;
		this.document = domDocument;
        this.factory = factory;
	}

	/**
	 * Generates a DOM element (XML) representing the <code>IDCard</code>.
	 * Currently the IDCard is represented as a SAML assertion.
	 */
	public Element buildDOMElement() {

		Element elem = document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION_PREFIXED);

        String sealMsgVersion = SOSIFactory.PROPERTYVALUE_SOSI_SEAL_MESSAGE_VERSION;
        if(factory != null)
            sealMsgVersion = factory.getProperties().getProperty(SOSIFactory.PROPERTYNAME_SOSI_SEAL_MESSAGE_VERSION, SOSIFactory.PROPERTYVALUE_SOSI_SEAL_MESSAGE_VERSION);
        if("1.0_0".equals(sealMsgVersion)) {
            elem.setAttributeNS(null, IDValues.id, IDValues.IDCARD);
        } else if("1.0_1".equals(sealMsgVersion)) {
            elem.setAttributeNS(null, IDValues.id, IDValues.IDCARD);
        } else if("1.0_2".equals(sealMsgVersion)) {
            elem.setAttributeNS(null, IDValues.ID, IDValues.IDCARD);
        }

        boolean useZuluTime = DGWSConstants.VERSION_1_0_1.equals(idCard.getVersion());

        elem.setAttributeNS(null, SAMLAttributes.ISSUE_INSTANT, XmlUtil.toXMLTimeStamp(idCard.getCreatedDate(), useZuluTime));
		elem.setAttributeNS(null, SAMLAttributes.VERSION, SAML_MAJOR_VERSION + "." + SAML_MINOR_VERSION);
		elem.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:" + NameSpaces.NS_SAML, NameSpaces.SAML2ASSERTION_SCHEMA);
		elem.setAttributeNS(NameSpaces.XMLNS_SCHEMA, "xmlns:" + NameSpaces.NS_DS, NameSpaces.DSIG_SCHEMA);

		// Add the IDCard ID to the IDResolver (wsu:id elements cannot be found
		// otherwise)
		IdResolver.registerElementById(elem, IDValues.IDCARD);

		Element issuerElem = document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ISSUER_PREFIXED);
		String issuer = idCard.getIssuer();
		issuerElem.appendChild(document.createTextNode(issuer));
		elem.appendChild(issuerElem);

		// <saml:AttributeStatement>
		elem.appendChild(buildSubject());

		// <saml:Conditions NotBefore="2006-01-05T07:53:00.00Z"
		// NotOnOrAfter="2006-01-06T07:53:00.000Z"/>
		Element condition = document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.CONDITIONS_PREFIXED);
		condition.setAttributeNS(null, SAMLAttributes.NOT_BEFORE, XmlUtil.toXMLTimeStamp(idCard.getCreatedDate(), useZuluTime));
		condition.setAttributeNS(null, SAMLAttributes.NOT_ON_OR_AFTER, XmlUtil.toXMLTimeStamp(idCard.getExpiryDate(), useZuluTime));
		elem.appendChild(condition);

		elem.appendChild(buildIDCardAttributes());
		if (idCard instanceof UserIDCard) {
			elem.appendChild(buildUserLog(((UserIDCard) idCard).getUserInfo()));
		}
		elem.appendChild(buildSystemLog(((SystemIDCard) idCard).getSystemInfo()));

		return elem;
	}

	// ======================================
	// Private helpers
	// ======================================
	private Element buildSystemLog(SystemInfo info) {

		Element data = samlUtil.createSAMLAttributeStatement(document, IDValues.SYSTEM_LOG);
		samlUtil.createSAMLAttribute(document, MedcomAttributes.IT_SYSTEM_NAME, info.getITSystemName(), data);
		Element careProvider = samlUtil.createSAMLAttribute(document, MedcomAttributes.CARE_PROVIDER_ID, info.getCareProvider().getID(), data);
		careProvider.setAttributeNS(null, SAMLAttributes.NAME_FORMAT, info.getCareProvider().getType());
		samlUtil.createSAMLAttribute(document, MedcomAttributes.CARE_PROVIDER_NAME, info.getCareProvider().getOrgName(), data);
		return data;
	}

	private Element buildUserLog(UserInfo info) {

		Element data = samlUtil.createSAMLAttributeStatement(document, IDValues.USER_LOG);
		if (!ModelUtil.isEmpty(info.getCPR()))
			samlUtil.createSAMLAttribute(document, MedcomAttributes.USER_CIVIL_REGISTRATION_NUMBER, info.getCPR(), data);

		samlUtil.createSAMLAttribute(document, MedcomAttributes.USER_GIVEN_NAME, info.getGivenName(), data);
		samlUtil.createSAMLAttribute(document, MedcomAttributes.USER_SURNAME, info.getSurName(), data);

		if (!ModelUtil.isEmpty(info.getEmail()))
			samlUtil.createSAMLAttribute(document, MedcomAttributes.USER_EMAIL_ADDRESS, info.getEmail(), data);

		samlUtil.createSAMLAttribute(document, MedcomAttributes.USER_ROLE, info.getRole(), data);

		if (!ModelUtil.isEmpty(info.getAuthorizationCode()))
			samlUtil.createSAMLAttribute(document, MedcomAttributes.USER_AUTHORIZATION_CODE, info.getAuthorizationCode(), data);

		if (!ModelUtil.isEmpty(info.getOccupation()))
			samlUtil.createSAMLAttribute(document, MedcomAttributes.USER_OCCUPATION, info.getOccupation(), data);

		return data;
	}

	private Element buildIDCardAttributes() {

		Element data = samlUtil.createSAMLAttributeStatement(document, IDValues.IDCARD_DATA);
		samlUtil.createSAMLAttribute(document, SOSIAttributes.IDCARD_ID, idCard.getIDCardID(), data);
		samlUtil.createSAMLAttribute(document, SOSIAttributes.IDCARD_VERSION, idCard.getVersion(), data);
		samlUtil.createSAMLAttribute(document, SOSIAttributes.IDCARD_TYPE, getIDCardType(), data);
		samlUtil.createSAMLAttribute(document, SOSIAttributes.AUTHENTICATION_LEVEL, Integer.toString(idCard.getAuthenticationLevel().getLevel()), data);

		if(idCard.getCertHash() != null) {
			samlUtil.createSAMLAttribute(document, SOSIAttributes.OCES_CERT_HASH, idCard.getCertHash(), data);
		}
		return data;
	}

	private String getIDCardType() {

		String result;
		if (idCard instanceof UserIDCard)
			result = IDCard.IDCARDTYPE_USER;
		else
			result = IDCard.IDCARDTYPE_SYSTEM;
		return result;
	}

	private Node buildSubject() {

		// <saml:Subject>
		// <saml:NameID> ...</saml:NameID>
		// ...
		// </saml:Subject>
		Element subj = document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.SUBJECT_PREFIXED);
		Element nameID = document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.NAMEID_PREFIXED);
		subj.appendChild(nameID);
		if (idCard.getAlternativeIdentifier() != null) {
			nameID.setAttributeNS(null, SAMLAttributes.FORMAT, SubjectIdentifierTypeValues.OTHER);
			nameID.appendChild(document.createTextNode(idCard.getAlternativeIdentifier()));
		} else if (idCard instanceof UserIDCard) {
			nameID.setAttributeNS(null, SAMLAttributes.FORMAT, SubjectIdentifierTypeValues.CPR_NUMBER);
			UserIDCard idc = (UserIDCard) idCard;
			nameID.appendChild(document.createTextNode(idc.getUserInfo().getCPR()));
		} else {
			SystemIDCard idc = (SystemIDCard) idCard;
			CareProvider cp = idc.getSystemInfo().getCareProvider();
			nameID.setAttributeNS(null, SAMLAttributes.FORMAT, cp.getType());
			nameID.appendChild(document.createTextNode(cp.getID()));
		}

		if ( ! AuthenticationLevel.NO_AUTHENTICATION.equals(idCard.getAuthenticationLevel())) {

            Element conf = (Element) subj.appendChild(document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.SUBJECT_CONFIRMATION_PREFIXED));

            String sealMsgVersion = SOSIFactory.PROPERTYVALUE_SOSI_SEAL_MESSAGE_VERSION;
            if(factory != null)
                sealMsgVersion = factory.getProperties().getProperty(SOSIFactory.PROPERTYNAME_SOSI_SEAL_MESSAGE_VERSION, SOSIFactory.PROPERTYVALUE_SOSI_SEAL_MESSAGE_VERSION);
            if("1.0_0".equals(sealMsgVersion)) {
                Element confMethod = (Element) conf.appendChild(document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.CONFIRMATION_METHOD_PREFIXED));
                confMethod.appendChild(document.createTextNode(HOLDER_OF_KEY));
            } else if("1.0_1".equals(sealMsgVersion)) {
                Element confMethod = (Element) conf.appendChild(document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.CONFIRMATION_METHOD_PREFIXED));
                confMethod.appendChild(document.createTextNode(HOLDER_OF_KEY));
            } else if("1.0_2".equals(sealMsgVersion)) {
                conf.setAttributeNS(null, "Method", HOLDER_OF_KEY);
            }

            Element confData = (Element) conf.appendChild(document.createElementNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.SUBJECT_CONFIRMATION_DATA_PREFIXED));
            if (AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION.equals(idCard.getAuthenticationLevel())) {
            	Element usernameToken = (Element) confData.appendChild(document.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.USERNAME_TOKEN_PREFIXED));
            	Element username = (Element) usernameToken.appendChild(document.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.USERNAME_PREFIXED));
            	username.appendChild(document.createTextNode(idCard.getUsername()));
            	Element password = (Element) usernameToken.appendChild(document.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.PASSWORD_PREFIXED));
            	password.appendChild(document.createTextNode(idCard.getPassword()));
            } else {
            	Element keyInfo = (Element) confData.appendChild(document.createElementNS(NameSpaces.DSIG_SCHEMA, SAMLTags.KEY_INFO_PREFIXED));
            	Element keyName = (Element) keyInfo.appendChild(document.createElementNS(NameSpaces.DSIG_SCHEMA, SAMLTags.KEY_NAME_PREFIXED));
            	keyName.appendChild(document.createTextNode(IDValues.OCES_SIGNATURE));
            }
		}

		return subj;
	}
}
