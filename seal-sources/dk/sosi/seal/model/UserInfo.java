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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/UserInfo.java $
 * $Id: UserInfo.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.model;

import java.io.Serializable;

/**
 * This class holds immutable attributes a user.
 *
 * @author Jan Riis
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public class UserInfo implements Serializable {

	private static final long serialVersionUID = -613253968267092558L;

	private final String cpr;
	private final String givenName;
	private final String surName;
	private final String email;
	private final String role;
	private final String authorizationCode;
	private final String occupation;


    /**
     * Constructs a <code>UserInfo</code> instance, copying data from the original.
     * This is a copy-constructor
     *
     * @param original UserInfoto copy data from.
     * @param cpr
 *            Civil Registration number for the user to use instead of the cpr inside the supplied userInfo
     */
    public UserInfo(UserInfo original, String cpr) {
        this(cpr, original.givenName, original.surName, original.email, original.occupation, original.role, original.authorizationCode);
    }

	/**
	 * Constructs a <code>UserInfo</code> instance.
	 *
	 * @param cpr
	 *            Civil Registration number for the user
	 * @param givenName
	 *            Given name of the user (da:fornavn)
	 * @param surName
	 *            Surname of the user (da:Efternavn)
	 * @param email
	 *            The users e-mail address
	 * @param occupation
	 * 			  The occupation for the user
	 * @param role
	 *            The role in which the user is acting, for instance doctor or
	 *            Nurse
	 * @param authorizationCode
	 *            The authorization code for the user (SST)
	 */
	public UserInfo(String cpr, String givenName, String surName, String email, String occupation, String role, String authorizationCode) {
		super();
		if(cpr == null) cpr = "";
		ModelUtil.validateNotEmpty(givenName, "UserGivenName must be specified");
		ModelUtil.validateNotEmpty(surName, "UserSurName must be specified");
		ModelUtil.validateNotEmpty(role, "UserRole must be specified");
		this.cpr = cpr;
		this.givenName = givenName;
		this.surName = surName;
		this.email = email;
		this.occupation = occupation;
		this.role = role;
		this.authorizationCode = authorizationCode;
	}

	/**
	 * @see #UserInfo(String, String, String, String, String, String, String)
	 */
	public String getCPR() {

		return cpr;
	}

	/**
	 * @see #UserInfo(String, String, String, String, String, String, String)
	 */
	public String getGivenName() {

		return givenName;
	}

	/**
	 * @see #UserInfo(String, String, String, String, String, String, String)
	 */
	public String getSurName() {

		return surName;
	}

	/**
	 * @see #UserInfo(String, String, String, String, String, String, String)
	 */
	public String getEmail() {

		return email;
	}

	/**
	 * @see #UserInfo(String, String, String, String, String, String, String)
	 */
	public String getOccupation() {
		return occupation;
	}

	/**
	 * @see #UserInfo(String, String, String, String, String, String, String)
	 */
	public String getRole() {

		return role;
	}

	/**
	 * @see #UserInfo(String, String, String, String, String, String, String)
	 */
	public String getAuthorizationCode() {

		return authorizationCode;
	}

	// =============================
	// Overridden parts
	// =============================
	public boolean equals(Object obj) {

		return obj == this || obj != null && obj.getClass() == getClass() && obj.hashCode() == hashCode() && cpr.equals(((UserInfo) obj).getCPR())
				&& givenName.equals(((UserInfo) obj).getGivenName()) && surName.equals(((UserInfo) obj).getSurName())
				&& safeEquals(email, ((UserInfo) obj).getEmail()) && role.equals(((UserInfo) obj).getRole())
				&& safeEquals(authorizationCode, ((UserInfo) obj).getAuthorizationCode())
				&& safeEquals(occupation, ((UserInfo) obj).getOccupation());
	}

	public int hashCode() {

		return cpr.hashCode() ^ givenName.hashCode() ^ surName.hashCode() ^ safeHashCode(email) ^ role.hashCode() ^ safeHashCode(authorizationCode) ^ safeHashCode(occupation);
	}

	private boolean safeEquals(Object a, Object b) {
		return a == b || a != null && a.equals(b);
	}

	private int safeHashCode(Object o) {
		return o == null ? 0 : o.hashCode();
	}
}