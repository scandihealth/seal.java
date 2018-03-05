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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/constants/SAMLTags.java $
 * $Id: SAMLTags.java 10510 2012-12-07 11:41:39Z ChristianGasser $
 */
package dk.sosi.seal.model.constants;

/**
 * Class containing SAML XML tags.
 * 
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public enum SAMLTags implements Tag {
    assertion("Assertion"),
    encryptedAssertion("EncryptedAssertion"),
    conditions("Conditions"), 
    audienceRestriction("AudienceRestriction"),
    attributeStatement("AttributeStatement"),
    attribute("Attribute"),
    attributeValue("AttributeValue"),
    authnStatement("AuthnStatement"),
    authnContext("AuthnContext"),
    authnContextClassRef("AuthnContextClassRef"),
    audience("Audience"),
    subject("Subject"),
    issuer("Issuer"),
    nameID("NameID"),
    subjectConfirmationData("SubjectConfirmationData"),
    subjectConfirmation("SubjectConfirmation"),
    ;

    public static final String ASSERTION = "Assertion";
    public static final String ENCRYPTED_ASSERTION = "EncryptedAssertion";
    public static final String ISSUER = "Issuer";
    public static final String CONDITIONS = "Conditions";
    public static final String SUBJECT = "Subject";
    public static final String NAMEID = "NameID";
    public static final String SUBJECT_CONFIRMATION = "SubjectConfirmation";
    public static final String CONFIRMATION_METHOD = "ConfirmationMethod";
    public static final String SUBJECT_CONFIRMATION_DATA = "SubjectConfirmationData";
    public static final String ATTRIBUTE_STATEMENT = "AttributeStatement";
    public static final String ATTRIBUTE = "Attribute";
    public static final String ATTRIBUTE_VALUE = "AttributeValue";

    public static final String ASSERTION_PREFIXED = NameSpaces.NS_SAML + ":" + ASSERTION;
    public static final String ENCRYPTED_ASSERTION_PREFIXED = NameSpaces.NS_SAML + ":" + ENCRYPTED_ASSERTION;
    public static final String ISSUER_PREFIXED = NameSpaces.NS_SAML + ":" + ISSUER;
    public static final String CONDITIONS_PREFIXED = NameSpaces.NS_SAML + ":" + CONDITIONS;
    public static final String SUBJECT_PREFIXED = NameSpaces.NS_SAML + ":" + SUBJECT;
    public static final String NAMEID_PREFIXED = NameSpaces.NS_SAML + ":" + NAMEID;
    public static final String SUBJECT_CONFIRMATION_PREFIXED = NameSpaces.NS_SAML + ":" + SUBJECT_CONFIRMATION;
    public static final String CONFIRMATION_METHOD_PREFIXED = NameSpaces.NS_SAML + ":" + CONFIRMATION_METHOD;
    public static final String SUBJECT_CONFIRMATION_DATA_PREFIXED = NameSpaces.NS_SAML + ":" + SUBJECT_CONFIRMATION_DATA;
    public static final String ATTRIBUTE_STATEMENT_PREFIXED = NameSpaces.NS_SAML + ":" + ATTRIBUTE_STATEMENT;
    public static final String ATTRIBUTE_PREFIXED = NameSpaces.NS_SAML + ":" + ATTRIBUTE;

    public static final String KEY_INFO_PREFIXED = NameSpaces.NS_DS + ":KeyInfo";
    public static final String KEY_NAME_PREFIXED = NameSpaces.NS_DS + ":KeyName";

    private final String tag;

    private SAMLTags(String tag) {
        this.tag = tag;
    }

    public String getNS() {
        return NameSpaces.SAML2ASSERTION_SCHEMA;
    }

    public String getTagName() {
        return tag;
    }

    public String getPrefix() {
        return NameSpaces.NS_SAML;
    }
}