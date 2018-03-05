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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/IDCardValidator.java $
 * $Id: IDCardValidator.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.model.constants.MedcomAttributes;

import java.util.HashSet;
import java.util.Set;

/**
 * IDCardValidator for validating IDCards
 * The IDCardValidator is used on things not validated by the schema
 *
 * @author ${user}
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.3
 */
public class IDCardValidator {

	private Set<String> attributes;

	public IDCardValidator() {
		attributes = new HashSet<String>();
		attributes.add(MedcomAttributes.IT_SYSTEM_NAME);
		attributes.add(MedcomAttributes.CARE_PROVIDER_ID);
		attributes.add(MedcomAttributes.CARE_PROVIDER_NAME);
		attributes.add(MedcomAttributes.USER_GIVEN_NAME);
		attributes.add(MedcomAttributes.USER_SURNAME);
		attributes.add(MedcomAttributes.USER_CIVIL_REGISTRATION_NUMBER);
	}

	public boolean remove(String tag) {
		return attributes.remove(tag);
	}

	public boolean add(String tag) {
		return attributes.add(tag);
	}

	/**
	 * Validates IDCard content in different contexts
	 *
	 * @param idCard
	 */
	public void validateIDCard(IDCard idCard) {
		if (idCard == null) {
			throw new ModelException("IDCard cannot be null!");
		}

		validateIDCardData(idCard);
		validateSystemInfo(((SystemIDCard)idCard).getSystemInfo());
		if(idCard instanceof UserIDCard) {
			boolean allowEmptyCPR =
				idCard.getAuthenticationLevel().getLevel() < AuthenticationLevel.VOCES_TRUSTED_SYSTEM.getLevel()
				&& ! ModelUtil.isEmpty(idCard.getAlternativeIdentifier());
			validateUserInfo(((UserIDCard)idCard).getUserInfo(), allowEmptyCPR);
		}
	}

	// other data gets implicit validated by seal parser
	private void validateIDCardData(IDCard idCard) {
		ModelUtil.validateNotEmpty(idCard.getIDCardID(), "IDCard ID cannot be empty");
	}

	private void validateSystemInfo(SystemInfo sysInfo) {
		if (sysInfo == null) {
			throw new ModelException("No SystemInfo present in IDCard!");
		}
		if(attributes.contains(MedcomAttributes.IT_SYSTEM_NAME))
			ModelUtil.validateNotEmpty(sysInfo.getITSystemName(), "ITSystemName cannot be empty");
		if(attributes.contains(MedcomAttributes.CARE_PROVIDER_ID))
			ModelUtil.validateNotEmpty(sysInfo.getCareProvider().getID(), "CareProviderID cannot be empty");
		if(attributes.contains(MedcomAttributes.CARE_PROVIDER_NAME))
			ModelUtil.validateNotEmpty(sysInfo.getCareProvider().getOrgName(), "CareProviderName cannot be empty");
	}

	private void validateUserInfo(UserInfo userInfo, boolean allowEmptyCPR) {
		if (userInfo == null) {
			throw new ModelException("No UserInfo present in IDCard!");
		}
		if(attributes.contains(MedcomAttributes.USER_GIVEN_NAME))
			ModelUtil.validateNotEmpty(userInfo.getGivenName(), "GivenName cannot be empty");
		if(attributes.contains(MedcomAttributes.USER_SURNAME))
			ModelUtil.validateNotEmpty(userInfo.getSurName(), "SurName cannot be empty");
		if(attributes.contains(MedcomAttributes.USER_CIVIL_REGISTRATION_NUMBER) && ! allowEmptyCPR)
			ModelUtil.validateNotEmpty(userInfo.getCPR(), "CPR cannot be empty");
	}
}
