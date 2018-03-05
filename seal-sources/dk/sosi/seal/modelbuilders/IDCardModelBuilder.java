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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/modelbuilders/IDCardModelBuilder.java $
 * $Id: IDCardModelBuilder.java 20605 2014-10-24 12:30:53Z ChristianGasser $
 */
package dk.sosi.seal.modelbuilders;

import dk.sosi.seal.model.*;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.xml.XmlUtil;
import org.apache.xml.security.utils.IdResolver;
import org.w3c.dom.*;

import java.text.ParseException;
import java.util.Date;

/**
 * Builds ID-card model objects from a DOM document.
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class IDCardModelBuilder { // NOPMD

	/**
	 * Builds an ID-card objects from a DOM document.
	 *
	 * @param doc
	 *            The DOM document used for the ID-card.
	 */
	public IDCard buildModel(Document doc) throws ModelBuildException {

		IDCard result = null;

        NodeList assertions = doc.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ASSERTION);
        for (int i = 0; i < assertions.getLength(); i++) {
            Element elem = (Element) assertions.item(i);
            XmlUtil.registerElementByIdExtended(elem);
            Element idCardElement = IdResolver.getElementById(doc, IDValues.IDCARD);
            if (idCardElement != null) {
                result = internalBuild(idCardElement);
                break;
            }
        }
		return result;
	}

    /**
     * Builds an ID-card object from a DOM element.
     *
     * @param assertion
     *            The DOM element for the ID-card
     */
    public IDCard buildModel(Element assertion) {
        return internalBuild(assertion);
    }


    private IDCard internalBuild(Element idCardElement) {
        IDCard result;
        String itSystemName = null, ocesCertHash = null, id = null, version = null,
        cpr = null, givenName = null, surName = null, email = null, occupation = null, userRole = null,
        authorizationCode = null, careProviderID = null, careProviderIDType = null,
        careProviderName = null, authLevel = null;
        boolean hasIDCardData = false, hasSystemLog=false, hasUserLog=false;

        String alternativeIdentifier = null;
        String username = null;
        String password = null;

        Date createdDate, expiryDate;

        // Check validity interval
        Node timeConstraints = idCardElement.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.CONDITIONS).item(0);
        NamedNodeMap conditionsAttributes = timeConstraints.getAttributes();
        try {
            expiryDate = XmlUtil.fromXMLTimeStamp(conditionsAttributes.getNamedItem(SAMLAttributes.NOT_ON_OR_AFTER).getNodeValue());
            createdDate = XmlUtil.fromXMLTimeStamp(conditionsAttributes.getNamedItem(SAMLAttributes.NOT_BEFORE).getNodeValue());
        } catch (DOMException e) {
            throw new ModelBuildException("SAML:Conditions could not be found", e);
        } catch (ParseException e) {
            throw new ModelBuildException("SAML:Conditions could not be parsed", e);
        }

        //Check for an alternative Identifier
        Node subjectNameIdNode = idCardElement.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.NAMEID).item(0);
        NamedNodeMap nameIdAttributes = subjectNameIdNode.getAttributes();
        Node nameIdFormatNode = nameIdAttributes.getNamedItem(SAMLAttributes.FORMAT);
        if (nameIdFormatNode.getFirstChild().getNodeValue().equals(SubjectIdentifierTypeValues.OTHER)) {
            alternativeIdentifier = subjectNameIdNode.getFirstChild().getNodeValue();
        }

        //AuthenticationLevel 2
        Element usernameTokenElement = (Element) idCardElement.getElementsByTagNameNS(NameSpaces.WSSE_SCHEMA, WSSETags.USERNAME_TOKEN).item(0);
        if (usernameTokenElement != null) {
            Node usernameNode = usernameTokenElement.getElementsByTagNameNS(NameSpaces.WSSE_SCHEMA, WSSETags.USERNAME).item(0);
            username = XmlUtil.getTextNodeValue(usernameNode);
            Node passwordNode = usernameTokenElement.getElementsByTagNameNS(NameSpaces.WSSE_SCHEMA, WSSETags.PASSWORD).item(0);
            password = XmlUtil.getTextNodeValue(passwordNode);

        }

        // IDCard attributes
        Node issuerNode = idCardElement.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ISSUER).item(0);
        String issuer = issuerNode.getFirstChild().getNodeValue();

        NodeList attributeStatementNodeList = idCardElement.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ATTRIBUTE_STATEMENT);

        Boolean isUserIDCard = null;
        for (int nodeCount = 0; nodeCount < attributeStatementNodeList.getLength(); nodeCount++) {
            NamedNodeMap map = attributeStatementNodeList.item(nodeCount).getAttributes();

            for (int attributeCount = 0; attributeCount < map.getLength(); attributeCount++) {

                String attributeValue = map.item(attributeCount).getNodeValue();

                if (IDValues.SYSTEM_LOG.equals(attributeValue)) {
                    // Iterate saml:Attributes in SystemLog
                    NodeList samlAttributeNodes = ((Element) attributeStatementNodeList.item(nodeCount)).getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ATTRIBUTE);

                    for (int samlAttributeCount = 0; samlAttributeCount < samlAttributeNodes.getLength(); samlAttributeCount++) {
                        Element samlAttribute = (Element) samlAttributeNodes.item(samlAttributeCount);
                        String attributeName = samlAttribute.getAttributes().getNamedItem(SAMLAttributes.NAME).getNodeValue();
                        String attributeNameValue = getAttributeNameValue(samlAttribute, attributeName);
                        if (MedcomAttributes.IT_SYSTEM_NAME.equals(attributeName)) {
                            itSystemName = attributeNameValue;
                        } else if (MedcomAttributes.CARE_PROVIDER_ID.equals(attributeName)) {
                            careProviderID = attributeNameValue;
                            Node nameFormatAttribute = samlAttribute.getAttributes().getNamedItem(SAMLAttributes.NAME_FORMAT);
                            if (nameFormatAttribute == null) {
                                throw new ModelBuildException("DGWS violation: 'medcom:CareProviderID' SAML attribute must contain a 'NameFormat' attribute!");
                            }
                            careProviderIDType = nameFormatAttribute.getNodeValue();
                        } else if (MedcomAttributes.CARE_PROVIDER_NAME.equals(attributeName)) {
                            careProviderName = attributeNameValue;
                        }
                    }
                    hasSystemLog = true;
                } else if (IDValues.IDCARD_DATA.equals(attributeValue)) {
                    // Iterate saml:Attributes in IDCard
                    NodeList samlAttributeNodes = ((Element) attributeStatementNodeList.item(nodeCount)).getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ATTRIBUTE);

                    for (int samlAttributeCount = 0; samlAttributeCount < samlAttributeNodes.getLength(); samlAttributeCount++) {
                        Element samlAttribute = (Element) samlAttributeNodes.item(samlAttributeCount);
                        String attributeName = samlAttribute.getAttributes().getNamedItem(SAMLAttributes.NAME).getNodeValue();
                        String attributeNameValue = getAttributeNameValue(samlAttribute, attributeName);
                        // Cert Hash
                        if (SOSIAttributes.OCES_CERT_HASH.equals(attributeName)) {
                            ocesCertHash = attributeNameValue;
                            // CardID
                        } else if (SOSIAttributes.IDCARD_ID.equals(attributeName)) {
                            id = attributeNameValue;
                            // CardVersion
                        } else if (SOSIAttributes.IDCARD_VERSION.equals(attributeName)) {
                            version = attributeNameValue;
                            // IDCardType
                        } else if (SOSIAttributes.IDCARD_TYPE.equals(attributeName)) {
                            if (IDCard.IDCARDTYPE_USER.equals(attributeNameValue))
                                isUserIDCard = Boolean.TRUE;
                            else if (IDCard.IDCARDTYPE_SYSTEM.equals(attributeNameValue))
                                isUserIDCard = Boolean.FALSE;
                        } else if (SOSIAttributes.AUTHENTICATION_LEVEL.equals(attributeName)) {
                            authLevel = attributeNameValue;
                        }
                    }
                    hasIDCardData = true;
                } else if (IDValues.USER_LOG.equals(attributeValue)) {
                    // Iterate saml:Attributes in UserLog
                    NodeList samlAttributeNodes = ((Element) attributeStatementNodeList.item(nodeCount)).getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ATTRIBUTE);

                    for (int samlAttributeCount = 0; samlAttributeCount < samlAttributeNodes.getLength(); samlAttributeCount++) {
                        Element samlAttribute = (Element) samlAttributeNodes.item(samlAttributeCount);
                        String attributeName = samlAttribute.getAttributes().getNamedItem(SAMLAttributes.NAME).getNodeValue();
                        String attributeNameValue = getAttributeNameValue(samlAttribute, attributeName);
                        if (MedcomAttributes.USER_CIVIL_REGISTRATION_NUMBER.equals(attributeName)) {
                            cpr = attributeNameValue;
                        } else if (MedcomAttributes.USER_GIVEN_NAME.equals(attributeName)) {
                            givenName = attributeNameValue;
                        } else if (MedcomAttributes.USER_SURNAME.equals(attributeName)) {
                            surName = attributeNameValue;
                        } else if (MedcomAttributes.USER_EMAIL_ADDRESS.equals(attributeName)) {
                            email = attributeNameValue;
                        } else if (MedcomAttributes.USER_OCCUPATION.equals(attributeName)) {
                            occupation = attributeNameValue;
                        } else if (MedcomAttributes.USER_ROLE.equals(attributeName)) {
                            userRole = attributeNameValue;
                        } else if (MedcomAttributes.USER_AUTHORIZATION_CODE.equals(attributeName)) {
                            authorizationCode = attributeNameValue;
                        }
                    }
                    hasUserLog = true;
                }
            }
        }

        CareProvider careProvider = new CareProvider(careProviderIDType, careProviderID, careProviderName);
        SystemInfo systemInfo = new SystemInfo(careProvider, itSystemName);

        // All IDCard types must have a IDCardData element
        if(!hasIDCardData)  throw new ModelBuildException("IDCardData element missing for IDCard");

        // All IDCard types must have a SystemLog element
        if(!hasSystemLog)  throw new ModelBuildException("SystemLog element missing for IDCard");

        if (isUserIDCard == null)
            throw new ModelBuildException("ID Card type not found or invalid");
        else if (isUserIDCard.booleanValue()) {
            if(!hasUserLog) throw new ModelBuildException("UserLog element missing for UserIDCard");
            UserInfo userInfo = new UserInfo(cpr, givenName, surName, email, occupation, userRole, authorizationCode);
            result = new UserIDCard(version, idCardElement, id, AuthenticationLevel.getEnumeratedValue(Integer.parseInt(authLevel)), ocesCertHash,
                    issuer, systemInfo, userInfo, createdDate, expiryDate, alternativeIdentifier, username, password);
        } else {
            if(hasUserLog) throw new ModelBuildException("IDCard type is 'system', but also has a UserLog element (??)");
            result = new SystemIDCard(version, idCardElement, id, AuthenticationLevel.getEnumeratedValue(Integer.parseInt(authLevel)),
                    ocesCertHash, issuer, systemInfo, createdDate, expiryDate, alternativeIdentifier, username, password);
        }
        return result;
    }

    private String getAttributeNameValue(Element samlAttribute, String attributeName) {
        Element elmAttributeValue =  (Element) samlAttribute.getElementsByTagNameNS(NameSpaces.SAML2ASSERTION_SCHEMA, SAMLTags.ATTRIBUTE_VALUE).item(0);
        if (elmAttributeValue == null) throw new ModelBuildException("Missing 'saml:AttributeValue' element for 'saml:Attribute' element '" + attributeName + "'");
        return XmlUtil.getTextNodeValue(elmAttributeValue);
    }

}
