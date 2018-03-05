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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/SystemIDCard.java $
 * $Id: SystemIDCard.java 10505 2012-12-06 09:48:13Z ChristianGasser $
 */
package dk.sosi.seal.model;

import org.w3c.dom.Element;

import java.util.Date;

/**
 * A class that represents system ID-Cards. In this type only information about
 * the system that requested the ID-card, will be present.
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class SystemIDCard extends IDCard {

	private static final long serialVersionUID = -4772888735908535672L;

	private final SystemInfo systemInfo;

	/**
	 * Creates a brand new System ID-card.
	 * @param version
	 * 			  The version of this IDCard, corresponds to DGWS version
	 * @param authenticationLevel
	 *            The level of trust a system can have to this IDCard
	 * @param issuer
	 *            A <code>String</code> representing the system that issues
	 *            the ID-Card
	 * @param systemInfo
	 *            A reference to a <code>SystemInfo</code> instance containing
	 *            information about the system this <code>IDCard</code>
	 *            represents.
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
	public SystemIDCard(String version, AuthenticationLevel authenticationLevel, String issuer, SystemInfo systemInfo, String certHash, String alternativeIdentifier, String username, String password) {
		super(version, authenticationLevel, issuer, certHash, alternativeIdentifier, username, password);
		ModelUtil.validateNotNull(systemInfo, "SystemInfo must be specified");
		this.systemInfo = systemInfo;
	}

	/**
	 * Creates a new ID-card from "deserialization" of XML.
	 * @param version
	 * 			  The version of this IDCard, corresponds to DGWS version
	 * @param domElement
	 *            the DOM element that is getting unmarshalled
	 * @param cardID
	 *            the unmarshalled id of the card
	 * @param authenticationLevel
	 *            the unmarshalled authentication level
	 * @param certHash
	 *            A secure Hash value (SHA-1) of the certificate that has been
	 *            used to verify the credentials when issuing this IDCard.
	 * @param issuer
	 *            the unmarshalled issuer.
	 * @param systemInfo
	 *            the unmarshalled <code>SystemInfo</code> instance
	 * @param alternativeIdentifier
	 * 			  The unmarshalled alternative identifier for this <code>IDCard</code>
	 *            or <code>null</code>.
	 * @param username
	 *            The username to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
	 * @param password
	 *            The password to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
	 */
	public SystemIDCard(String version, Element domElement, String cardID, AuthenticationLevel authenticationLevel, String certHash,
			String issuer, SystemInfo systemInfo, Date creationDate, Date expiryDate, String alternativeIdentifier, String username, String password) {

		super(version, domElement, cardID, authenticationLevel, certHash, issuer, creationDate, expiryDate, alternativeIdentifier, username, password);
		ModelUtil.validateNotNull(systemInfo, "SystemInfo must be specified");
		this.systemInfo = systemInfo;
	}

	/**
	 * Creates a brand new <code>SystemIDCard</code> based on values from
	 * another <code>IDCard</code> instance. The constructed IDCard will get a
	 * new <code>id</code> and will scheduled for VOCES signing, making this
	 * constructor ideal for IdP ID-card issuers.
	 *
	 * @param toCopy
	 *            the <code>IDCard</code> to copy
	 * @param issuer
	 *            A <code>String</code> representing the system that issues
	 *            the ID-Card
	 */
	public SystemIDCard(SystemIDCard toCopy, String issuer) {

		super(toCopy, issuer);
		this.systemInfo = toCopy.getSystemInfo();
	}

	/**
	 * Creates a brand new <code>SystemIDCard</code> based on values from
	 * another <code>IDCard</code> instance. The constructed IDCard will get a
	 * new <code>id</code> and will scheduled for VOCES signing, making this
	 * constructor ideal for IdP ID-card issuers.
	 *
	 * @param toCopy
	 *            the <code>IDCard</code> to copy
	 * @param issuer
	 *            A <code>String</code> representing the system that issues
	 *            the ID-Card
	 * @param certHash
	 *            The hash code of the certificate that was used as credentials
	 *            for the issuance this IDCard. May be <code>null</code>.
	 */
	public SystemIDCard(SystemIDCard toCopy, String issuer, String certHash) {
        this(toCopy, issuer, certHash, null);
	}

    public SystemIDCard(SystemIDCard toCopy, String issuer, String certHash, String alternativeIdentifier) {
        super(toCopy, issuer, certHash, alternativeIdentifier);
        this.systemInfo = toCopy.getSystemInfo();
    }

    /**
	 * Returns the embedded <code>SystemInfo</code> instance.
	 */
	public SystemInfo getSystemInfo() {

		return systemInfo;
	}

	public boolean equals(Object obj) { // NOPMD

		return super.equals(obj) && obj.getClass() == getClass() && getSystemInfo().equals(((SystemIDCard) obj).getSystemInfo());
	}
}
