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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/UserIDCard.java $
 * $Id: UserIDCard.java 10505 2012-12-06 09:48:13Z ChristianGasser $
 */
package dk.sosi.seal.model;

import org.w3c.dom.Element;

import java.util.Date;

/**
 * Represents personal ID-cards. This type includes both information about the
 * user and the system through which the user is requesting the ID-card.
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class UserIDCard extends SystemIDCard {
	private static final long serialVersionUID = -3844876145617148725L;

	private final UserInfo userInfo;

	// ===============================
	// Constructors
	// ===============================

	/**
	 * Creates a brand new <code>UserIDCard</code> (no deserialization).
	 * @param version
	 * 			  The version of this IDCard, corresponds to DGWS version
	 * @param authenticationLevel
	 *            The level of trust a system can have to this ID card.
	 * @param issuer
	 *            A <code>String</code> representing the system that issues
	 *            the ID-Card
	 * @param systemInfo
	 *            A reference to a <code>SystemInfo</code> object containing
	 *            information about the system the user is operating on
	 * @param userInfo
	 *            A reference to a <code>UserInfo</code> object containing
	 *            specific information about the user
	 * @param certHash
	 *            A SHA-1 digest of the certificate that can validate this
	 *            ID-card. May be <code>null</code>.
	 * @param alternativeIdentifier
	 *            A <code>String</code> denoting an alternative identifier that
	 *            will be used as SAML Subject (of type medcom:other) when serializing
	 *            this IDCard instead. May be <code>null</null>.
	 * @param username
	 *            The username to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
	 * @param password
	 *            The password to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
	 */
	public UserIDCard(String version, AuthenticationLevel authenticationLevel, String issuer, SystemInfo systemInfo, UserInfo userInfo, String certHash, String alternativeIdentifier, String username, String password) {

		super(version, authenticationLevel, issuer, systemInfo, certHash, alternativeIdentifier, username, password);
		ModelUtil.validateNotNull(userInfo, "UserInfo must be specified");
		this.userInfo = userInfo;
	}

	/**
	 * Creates a new <code>UserIDCard</code> from deserializing a DOM element.
	 * @param version
	 * 			  The version of this IDCard, corresponds to DGWS version
	 * @param domElement
	 *            A reference to the DOM element that contains the values for
	 *            this ID card.
	 * @param cardID
	 *            The unmarshalled card ID.
	 * @param authenticationLevel
	 *            The level of trust a system can have to this ID card.
	 * @param certHash
	 *            A secure Hash value (SHA-1) of the certificate that has been
	 *            used to verify the credentials when issuing this IDCard.
	 * @param issuer
	 *            A <code>String</code> representing the system that issues
	 *            the ID-Card
	 * @param userInfo
	 *            A reference to the unmarshalled <code>UserInfo</code> object
	 *            containing specific information about the user
	 * @param createdDate
	 *            The expirydate (and time) for this IDCard
	 * @param expiryDate
	 *            The creationdate (and time) for this IDCard
	 * @param alternativeIdentifier
	 * 			  The unmarshalled alternative identifier for this <code>IDCard</code>
	 *            or <code>null</code>.
	 * @param username
	 *            The username to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
	 * @param password
	 *            The password to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
	 */
	public UserIDCard(String version, Element domElement, String cardID, AuthenticationLevel authenticationLevel, String certHash, String issuer,
			SystemInfo systemInfo, UserInfo userInfo, Date createdDate, Date expiryDate, String alternativeIdentifier, String username, String password) {

		super(version, domElement, cardID, authenticationLevel, certHash, issuer, systemInfo, createdDate, expiryDate, alternativeIdentifier, username, password);
		ModelUtil.validateNotNull(userInfo, "UserInfo must be specified");
		this.userInfo = userInfo;
	}

	/**
	 * Creates a new <code>UserIDCard</code> using an existing UserIDCard.
	 *
	 * @param original
	 *            the <code>UserIDCard</code> to copy
	 * @param issuer
	 *            A <code>String</code> representing the system that issues
	 *            the ID-Card
	 */
	public UserIDCard(UserIDCard original, String issuer) {
		this(original, issuer, null);
	}

	/**
	 * Creates a new <code>UserIDCard</code> using an existing UserIDCard.
	 *
	 * @param original
	 *            the <code>UserIDCard</code> to copy
	 * @param issuer
	 *            A <code>String</code> representing the system that issues
	 *            the ID-Card
	 * @param cpr
	 *            optional cpr to add if origCard doesnt contain it
	 */
	public UserIDCard(UserIDCard original, String issuer, String cpr) {
		super(original, issuer);
		this.userInfo = handleUserInfo(original, cpr);
	}

	/**
	 * Creates a new <code>UserIDCard</code> using an existing UserIDCard.
	 *
	 * @param original
	 *            the <code>UserIDCard</code> to copy
	 * @param issuer
	 *            A <code>String</code> representing the system that issues
	 *            the ID-Card
	 * @param cpr
	 *            optional cpr to add if origCard doesnt contain it
	 * @param certHash
	 *            The hash code of the certificate that was used as credentials
	 *            for the issuance this IDCard. May be <code>null</code>.
	 */
	public UserIDCard(UserIDCard original, String issuer, String cpr, String certHash) {
        this (original, issuer, handleUserInfo(original, cpr), certHash);
	}

    /**
     * Creates a new <code>UserIDCard</code> using an existing UserIDCard.
     *
     * @param original
     *            the <code>UserIDCard</code> to copy
     * @param issuer
     *            A <code>String</code> representing the system that issues
     *            the ID-Card
     * @param newUserInfo
     *            optional newUserInfo to use instead of th original info set on the original UserIDCard
     * @param certHash
     *            The hash code of the certificate that was used as credentials
     *            for the issuance this IDCard. May be <code>null</code>.
     */
    public UserIDCard(UserIDCard original, String issuer, UserInfo newUserInfo, String certHash) {
        this (original, issuer, newUserInfo, certHash, null);
    }

    /**
     * Creates a new <code>UserIDCard</code> using an existing UserIDCard.
     *
     * @param original
     *            the <code>UserIDCard</code> to copy
     * @param issuer
     *            A <code>String</code> representing the system that issues
     *            the ID-Card
     * @param newUserInfo
     *            optional newUserInfo to use instead of th original info set on the original UserIDCard
     * @param certHash
     *            The hash code of the certificate that was used as credentials
     *            for the issuance this IDCard. May be <code>null</code>.
     */
    public UserIDCard(UserIDCard original, String issuer, UserInfo newUserInfo, String certHash, String alternativeIdentifier) {
        super(original, issuer, certHash, alternativeIdentifier);
        this.userInfo = newUserInfo != null ? newUserInfo : original.userInfo;
    }

    /**
	 * Handles UserInfo creation
	 */
	private static UserInfo handleUserInfo(UserIDCard original, String cpr) {
		if(cpr == null || "".equals(cpr))
			return original.getUserInfo();
		else {
			UserInfo ui = original.getUserInfo();
			return new UserInfo(ui, cpr);
		}
	}

	// ===============================
	// Public methods
	// ===============================

	/**
	 * Returns information about the user, that this <code>UserIDCard</code>
	 * represents.
	 */
	public UserInfo getUserInfo() {

		return userInfo;
	}

	// ==========================================
	// Overridden parts
	// ==========================================

	public boolean equals(Object obj) { // NOPMD

		return super.equals(obj) && obj.getClass() == getClass() && getUserInfo().equals(((UserIDCard) obj).getUserInfo());
	}
}
