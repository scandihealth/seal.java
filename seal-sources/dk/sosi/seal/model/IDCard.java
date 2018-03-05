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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/IDCard.java $
 * $Id: IDCard.java 10505 2012-12-06 09:48:13Z ChristianGasser $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.DGWSConstants;
import dk.sosi.seal.model.constants.DSTags;
import dk.sosi.seal.model.constants.IDValues;
import dk.sosi.seal.model.constants.NameSpaces;
import dk.sosi.seal.model.dombuilders.IDCardDOMBuilder;
import dk.sosi.seal.pki.Federation;
import dk.sosi.seal.pki.SignatureProvider;
import dk.sosi.seal.pki.SignatureProviderFactory;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * An abstract class representing a SOSI ID card. Please refer to concrete subclasses for further information.
 * <p>
 * Subclasses of this class <b>must</b> be immutable. If not, the DOM caching will break.
 *
 * @author Jan Riis
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public abstract class IDCard implements Serializable {

    /** ID Card type for system ID cards */
    public static final String IDCARDTYPE_SYSTEM = "system";

    /** ID Card type for user (personal) ID cards */
    public static final String IDCARDTYPE_USER = "user";

    /**
     * Set the ID card starttime to "now" minus this amount of minutes, to circumvent minor differences in the
     * server/client clocks.
     */
    private static final int IDCARD_BEGIN_TIME_BUFFER_IN_MINUTES = 5;

    /**
     * Maximum lifetime of an ID-Card
     */
    private static final int MAX_IDCARD_LIFE_IN_HOURS = 24;

    private final String id;
    private final Date createdDate;
    private final Date expiryDate;
    private final String issuer;
    private final AuthenticationLevel authenticationLevel;
    private String certHash;
    private final String alternativeIdentifier;
    private String username;
    private String password;

    /** An DOM element that is the current representation of this IDCard. */
    // TODO: consider to make this element transient - BUT beware of dependencies to the "needsSignature" value and the
    // invariant needsSignature=(domElement==null)
    protected Element domElement = null;

    /** Does the IDCard need a signature */
    protected boolean needsSignature;

    /**
     * Indicates the last operation performed on the DOM element, i.e. CREATED, SIGNED etc.
     */
    protected String lastDOMOperation = null;

    /** State to indicate that DOM element has been created */
    protected static final String CREATED = "ObjectCreated";
    /** State to indicate that DOM element has been re-assigned */
    protected static final String RE_ASSIGNED = "NodeReAssignedToNewDocument";
    /** State to indicate that DOM element has been signed */
    protected static final String SIGNED = "SignatureCreated";

    private final String version;

    // ===========================================
    // Constructors
    // ===========================================

    /**
     * Constructs an <code>IDCard</code> instance.
     *
     * @param version
     *            The version of this IDCard, corresponds to DGWS version
     * @param domElement
     *            An optional DOM element that is the current representation of this IDCard.
     * @param cardID
     *            The unique ID for this IDCard instance.
     * @param authenticationLevel
     *            Specifies the authentication level for this ID-card, or more precisely the strength of the credentials
     *            the user/system presented when this ID-card was issued. Please refer to the "Den Gode Web Service"
     *            specification for more details.
     * @param certHash
     *            The hash code of the certificate that was used as credentials for the issuance this IDCard. May be
     *            <code>null</code>.
     * @param creationDate
     *            The unmarshalled expirydate (and time) for this <code>IDCard</code>
     * @param expiryDate
     *            The unmarshalled creationdate (and time) for this <code>IDCard</code>
     * @param alternativeIdentifier
     *            The unmarshalled alternative identifier for this <code>IDCard</code> or <code>null</code>.
     * @param username
     *            The username to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
     * @param password
     *            The password to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
     */
    IDCard(String version, Element domElement, String cardID, AuthenticationLevel authenticationLevel, String certHash,
           String issuer, Date creationDate, Date expiryDate, String alternativeIdentifier, String username,
           String password) {

        super();
        if(!DGWSConstants.SUPPORTED_VERSIONS.contains(version))
            throw new ModelException("IDCard version '" + version + "' not supported. Supported versions are: "
                                             + DGWSConstants.SUPPORTED_VERSIONS);
        ModelUtil.validateNotNull(cardID, "IDCard ID cannot be 'null'");
        ModelUtil.validateNotEmpty(issuer, "'Issuer' cannot be null or empty");
        ModelUtil.validateNotNull(authenticationLevel, "'AuthenticationLevel' cannot be null");

        this.version = version;
        this.createdDate = creationDate;
        this.expiryDate = expiryDate;
        this.issuer = issuer;
        this.authenticationLevel = authenticationLevel;
        if(AuthenticationLevel.MOCES_TRUSTED_USER.equals(authenticationLevel)
                || AuthenticationLevel.VOCES_TRUSTED_SYSTEM.equals(authenticationLevel)) {
            this.certHash = certHash;
        }
        this.domElement = domElement;
        this.alternativeIdentifier = alternativeIdentifier;
        if(AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION.equals(authenticationLevel)) {
            ModelUtil.validateNotEmpty(username, "'username' cannot be null or empty for authenticationlevel 2");
            ModelUtil.validateNotEmpty(password, "'password' cannot be null or empty for authenticationlevel 2");
            this.username = username;
            this.password = password;
        }

        // This is an invariant! When the IDCard is created from deserialization,
        // the ID card is already signed => needsSignature=false
        needsSignature = (domElement == null);

        id = cardID;
    }

    /**
     * Creates a brand new ID-card.
     *
     * @param version
     *            The version of this IDCard, corresponds to DGWS version
     * @param authenticationLevel
     *            The level of trust a system can have to this IDCard
     * @param issuer
     *            A <code>String</code> representing the system that issues the ID-Card
     * @param certHash
     *            A SHA-1 digest of the certificate that can validate this ID-card. May be <code>null</code>.
     * @param alternativeIdentifier
     *            A <code>String</code> denoting an alternative identifier that will be used as SAML Subject (of type
     *            medcom:other) when serializing this IDCard instead. May be <code>null</null>.
     * @param username
     *            The username to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
     * @param password
     *            The password to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
     */
    IDCard(String version, AuthenticationLevel authenticationLevel, String issuer, String certHash,
           String alternativeIdentifier, String username, String password) {
        super();
        if(!DGWSConstants.SUPPORTED_VERSIONS.contains(version))
            throw new ModelException("IDCard version '" + version + "' not supported. Supported versions are: "
                                             + DGWSConstants.SUPPORTED_VERSIONS);
        ModelUtil.validateNotEmpty(issuer, "'Issuer' cannot be null or empty");
        ModelUtil.validateNotNull(authenticationLevel, "'AuthenticationLevel' cannot be null");

        this.version = version;
        long starttime = System.currentTimeMillis() - IDCARD_BEGIN_TIME_BUFFER_IN_MINUTES * 60 * 1000;
        this.createdDate = new Date(starttime);
        this.expiryDate = new Date(starttime + MAX_IDCARD_LIFE_IN_HOURS * 60 * 60 * 1000);

        this.issuer = issuer;
        this.authenticationLevel = authenticationLevel;
        if(AuthenticationLevel.MOCES_TRUSTED_USER.equals(authenticationLevel)
                || AuthenticationLevel.VOCES_TRUSTED_SYSTEM.equals(authenticationLevel)) {
            this.certHash = certHash;
        }
        this.alternativeIdentifier = alternativeIdentifier;
        if(AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION.equals(authenticationLevel)) {
            ModelUtil.validateNotEmpty(username, "'username' cannot be null or empty for authenticationlevel 2");
            ModelUtil.validateNotEmpty(password, "'password' cannot be null or empty for authenticationlevel 2");
            this.username = username;
            this.password = password;
        }

        // This is an invariant! When the IDCard is created from deserialization,
        // the ID card is already signed => needsSignature=false
        needsSignature = (domElement == null);

        id = XmlUtil.createGUID();
    }

    /**
     * Creates a brand new ID-card based on values from another <code>IDCard</code> instance. The constructed IDCard
     * will get a new <code>id</code>, creation date/time, expiry date/time and will scheduled for VOCES signing, making
     * this constructor ideal for IdP ID-card issuers.
     *
     * @param toCopy
     *            the <code>IDCard</code> to copy
     * @param issuer
     *            A <code>String</code> representing the system that issues the ID-Card
     */
    IDCard(IDCard toCopy, String issuer) {
        this(toCopy, issuer, toCopy.getCertHash());
    }

    /**
     * Creates a brand new ID-card based on values from another <code>IDCard</code> instance. The constructed IDCard
     * will get a new <code>id</code>, creation date/time, expiry date/time and will scheduled for VOCES signing, making
     * this constructor ideal for STS ID-card issuers.
     *
     * @param toCopy
     *            the <code>IDCard</code> to copy
     * @param issuer
     *            A <code>String</code> representing the system that issues the ID-Card
     * @param certHash
     *            The hash code of the certificate that was used as credentials for the issuance this IDCard. May be
     *            <code>null</code>.
     */
    IDCard(IDCard toCopy, String issuer, String certHash) {
        this(toCopy, issuer, certHash, null);
    }

    public IDCard(IDCard toCopy, String issuer, String certHash, String alternativeIdentifier) {
        if(issuer == null)
            throw new ModelException("'Issuer' cannot be null");

        this.version = toCopy.getVersion();
        long starttime = System.currentTimeMillis() - IDCARD_BEGIN_TIME_BUFFER_IN_MINUTES * 60 * 1000;
        this.createdDate = new Date(starttime);
        this.expiryDate = new Date(starttime + MAX_IDCARD_LIFE_IN_HOURS * 60 * 60 * 1000);
        this.issuer = issuer;
        this.authenticationLevel = toCopy.getAuthenticationLevel();
        if(AuthenticationLevel.MOCES_TRUSTED_USER.equals(authenticationLevel)
                || AuthenticationLevel.VOCES_TRUSTED_SYSTEM.equals(authenticationLevel)) {
            this.certHash = certHash;
        }
        this.alternativeIdentifier = alternativeIdentifier != null ? alternativeIdentifier : toCopy.getAlternativeIdentifier();
        if(AuthenticationLevel.USERNAME_PASSWORD_AUTHENTICATION.equals(authenticationLevel)) {
            this.username = toCopy.getUsername();
            this.password = toCopy.getPassword();
        }

        // This is an invariant! When the IDCard is created from deserialization,
        // the ID card is already signed => needsSignature=false
        needsSignature = (domElement == null);
        id = XmlUtil.createGUID();
    }

    // ===========================================
    // Public methods
    // ===========================================

    /**
     * Validates the validity of the IDCard
     */
    public boolean isValidInTime() {
        Date now = new Date();
        return now.equals(getCreatedDate()) || now.after(getCreatedDate()) && now.before(getExpiryDate());
    }

    /**
     * Returns the version of this ID-Card
     */
    public String getVersion() {

        return version;
    }

    /**
     * Returns the ID of this ID-Card (unique in the federation).
     */
    public String getIDCardID() {

        return id;
    }

    /**
     * Returns the createdDate.
     */
    public Date getCreatedDate() {

        return createdDate;
    }

    /**
     * Returns the expiryDate.
     */
    public Date getExpiryDate() {

        return expiryDate;
    }

    /**
     * Returns the issuer.
     */
    public String getIssuer() {

        return issuer;
    }

    /**
     * Returns the authentication authenticationLevel for this IDCard. In essence this attribute tells how strong
     * identification credentials the user (or system) presented to the IDCard issuer. The stronger the credentials, the
     * higher authentication authenticationLevel.
     */
    public AuthenticationLevel getAuthenticationLevel() {

        return authenticationLevel;
    }

    /**
     * Returns the alternative identifier for this <code>IDCard</code> or <code>null</code> if no such identifier has
     * been specified.
     */
    public String getAlternativeIdentifier() {
        return alternativeIdentifier;
    }

    /**
     * Returns a SHA-1 digest of the certificate that can validate this ID-card.
     */
    public String getCertHash() {

        return certHash;
    }

    /**
     * @return The username to employ if this idcard has authenticationLevel 2. Otherwise <code>null</code>.
     */
    public String getUsername() {
        return username;
    }

    /**
     * @return The password to employ if this idcard has authenticationLevel 2. Otherwise <code>null</code>.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Signs a document.
     *
     * @param document
     *            The document to sign.
     * @param vault
     *            Object that gives access to credential information used for signing.
     * @deprecated Use {@link #sign(org.w3c.dom.Document, dk.sosi.seal.pki.SignatureProvider)} instead
     */
    @Deprecated
    public void sign(Document document, CredentialVault vault) {
        sign(document, SignatureProviderFactory.fromCredentialVault(vault));
    }

    /**
     * Signs a document.
     *
     * @param document
     *            The document to sign.
     * @param provider
     *            Object that gives access to sign method
     */
    public void sign(Document document, SignatureProvider provider) {
        if(needsSignature) {
            if(domElement == null) {
                throw new IllegalStateException("IDCard DOM has not been prepared");
            }
            final String[] referenceUris = { IDValues.IDCARD };
            final SignatureConfiguration configuration = new SignatureConfiguration(referenceUris, IDValues.IDCARD, IDValues.id);

            SignatureUtil.sign(provider, document, configuration);

            lastDOMOperation = SIGNED;
            needsSignature = false;
        }
    }

    /**
     * Returns a DOM document with the current DOM element representation of this IDCard.
     */
    public Element serialize2DOMDocument(SOSIFactory factory, Document doc) {
        if(domElement == null) {
            domElement = new IDCardDOMBuilder(factory, doc, this).buildDOMElement();
            lastDOMOperation = CREATED;
        }
        if(!domElement.getOwnerDocument().equals(doc)) {
            // Import the IDCard DOM element into the new document
            domElement = (Element)doc.importNode(domElement, true);
            lastDOMOperation = RE_ASSIGNED;
        }
        return domElement;
    }

    /**
     * Returns a <code>byte[]</code> containing the bytes that can be used to sign this <code>IDCard</code> object. This
     * method is useful for situations where the actual signature will be created externally e.g. in the situation where
     * an actual user has to be prompted for the MOCES signature. The actual signature is computed by:
     * <p/>
     * <ol>
     * <li>Using a <i>RSAwithSHA1</i> algoritm to digest and encrypt the bytes</li>
     * <li>Base64 encoding the signed byte array</li>
     * </ol>
     * <p/>
     * Please see the {@link #injectSignature(String, X509Certificate)} method for how to embed the signature into
     * <code>IDCard</code> objects.
     *
     * @param doc
     *            The DOM document to calculate the digest from.
     */
    public byte[] getBytesForSigning(Document doc) {
        SignatureConfiguration configuration = new SignatureConfiguration(new String[]{IDValues.IDCARD}, IDValues.IDCARD, IDValues.id);
        return SignatureUtil.getSignedInfoBytes(doc, configuration);
    }

    /**
     * Inserts a XML signature value into the XML document associated with this id card. This method is useful when
     * signing is done externally, e.g. when signing an <code>IDCard</code> using a MOCES private key.
     * <p/>
     * Please refer to {@link #getBytesForSigning(Document)} for details on how to calculate the actual signature value.
     *
     * @param signature
     *            A base 64 encoded string containing the RSA encrypted bytes of the &lt;ds:SignedInfo&gt; element
     *            calculated over this <code>IDCard</code>.
     * @param certificate
     *            The certificate used to create the signature
     */
    public void injectSignature(String signature, X509Certificate certificate) {
        if(getAuthenticationLevel().getLevel() < AuthenticationLevel.VOCES_TRUSTED_SYSTEM.getLevel())
            throw new ModelException("AuthenticationLevel does not support signature");

        if(domElement == null)
            throw new ModelException("DOM not initialized");
        Document document = domElement.getOwnerDocument();
        SignatureConfiguration configuration = new SignatureConfiguration((SignatureConfiguration.Reference[]) null, IDValues.IDCARD, null);
        SignatureUtil.injectSignature(document, signature, configuration, certificate, true);
        lastDOMOperation = SIGNED;
        needsSignature = false;
    }

    public X509Certificate getSignedByCertificate() {
        X509Certificate cert = null;
        if(getAuthenticationLevel().getLevel() >= AuthenticationLevel.VOCES_TRUSTED_SYSTEM.getLevel()
                && (domElement != null && !needsSignature)) {
            cert = SignatureUtil.getCertificateFromSignature(domElement);
        }
        return cert;
    }

    /**
     * Generates certHash from the idcards certificate.
     *
     * @return certHash
     */
    public String generateCertHash() {
        if(domElement == null)
            throw new ModelException("DOM not initialized");

        X509Certificate certificate = SignatureUtil.getCertificateFromSignature(domElement);
        return SignatureUtil.getDigestOfCertificate(certificate);
    }

    /**
     * Validates the signature on this idcard - no trust checks are performed
     *
     * @throws ModelException if the idcard is not signed or the signature is broken
     *
     * @since 2.1.6
     */
    public void validateSignature() {
        internalValidateSignature(null, null, false);
    }

    /**
     * Validates the signature on this idcard and checks trust against the supplied federation
     *
     * @param federation The federation to check trust against
     *
     * @throws ModelException if the idcard is not signed, the signature is broken or the signing
     * certificate is not trusted
     *
     * @since 2.1.6
     */
    public void validateSignatureAndTrust(Federation federation) {
        internalValidateSignature(federation, null, true);
    }

    /**
     * Validates the signature on this idcard and checks trust against the supplied credentialvault
     *
     * @param trustVault The credentialvault to check trust against
     *
     * @throws ModelException if the idcard is not signed, the signature is broken or the signing
     * certificate is not trusted
     *
     * @since 2.1.6
     */
    public void validateSignatureAndTrust(CredentialVault trustVault) {
        internalValidateSignature(null, trustVault, true);
    }

    private void internalValidateSignature(Federation federation, CredentialVault vault, boolean checkTrust) {
        if (getAuthenticationLevel().getLevel() < AuthenticationLevel.VOCES_TRUSTED_SYSTEM.getLevel()) {
            throw new ModelException("AuthenticationLevel does not support signature");
        }
        if (domElement == null) {
            throw new ModelException("DOM not initialized");
        }

        NodeList signatureElements = domElement.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE);
        if (signatureElements.getLength() == 0) {
            throw new ModelException("IDCard is not signed!");
        } else if (signatureElements.getLength() > 1) {
            throw new ModelException("Found more than one signature on IDCard!");
        } else {
            final Node signature = signatureElements.item(0);
            if (!SignatureUtil.validate(signature, federation, vault, checkTrust)) {
                throw new ModelException("Signature on IdCard could not be validated");
            }
        }
    }

    // ==========================================
    // Overridden parts
    // ==========================================

    /**
     * @see Object#equals(java.lang.Object)
     */
    public boolean equals(Object obj) {
        return obj == this || obj != null && obj.getClass() == getClass() && obj.hashCode() == hashCode()
                && getCreatedDate().getTime() / 1000 == ((IDCard)obj).getCreatedDate().getTime() / 1000
                && getExpiryDate().getTime() / 1000 == ((IDCard)obj).getExpiryDate().getTime() / 1000
                && getIssuer().equals(((IDCard)obj).getIssuer()) && getVersion().equals(((IDCard)obj).getVersion())
                && getAuthenticationLevel().equals(((IDCard)obj).getAuthenticationLevel())
                && safeEquals(getCertHash(), ((IDCard)obj).getCertHash())
                && safeEquals(getAlternativeIdentifier(), ((IDCard)obj).getAlternativeIdentifier())
                && safeEquals(getUsername(), ((IDCard)obj).getUsername())
                && safeEquals(getPassword(), ((IDCard)obj).getPassword());
    }

    /**
     * @see Object#hashCode()
     */
    public int hashCode() {

        return id.hashCode();
    }

    private boolean safeEquals(Object a, Object b) {
        return (a == null && b == null) || (a != null && a.equals(b));
    }

}
