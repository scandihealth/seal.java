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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/constants/MedcomAttributes.java $
 * $Id: MedcomAttributes.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.model.constants;

/**
 * XML attributes for being consistent with the MedCom web service standard.
 * 
 * @author kkj
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public interface MedcomAttributes {

	// saml:Attribute names for UserLog
	String USER_CIVIL_REGISTRATION_NUMBER = NameSpaces.NS_MEDCOM + ":UserCivilRegistrationNumber";
	String USER_GIVEN_NAME = NameSpaces.NS_MEDCOM + ":UserGivenName";
	String USER_SURNAME = NameSpaces.NS_MEDCOM + ":UserSurName";
	String USER_EMAIL_ADDRESS = NameSpaces.NS_MEDCOM + ":UserEmailAddress";
	String USER_OCCUPATION = NameSpaces.NS_MEDCOM + ":UserOccupation";
	String USER_ROLE = NameSpaces.NS_MEDCOM + ":UserRole";
	String USER_AUTHORIZATION_CODE = NameSpaces.NS_MEDCOM + ":UserAuthorizationCode";
	
	// saml:Attribute names for SystemLog
	String IT_SYSTEM_NAME = NameSpaces.NS_MEDCOM + ":ITSystemName";
	String CARE_PROVIDER_ID = NameSpaces.NS_MEDCOM + ":CareProviderID";
	String CARE_PROVIDER_NAME = NameSpaces.NS_MEDCOM + ":CareProviderName";

}
