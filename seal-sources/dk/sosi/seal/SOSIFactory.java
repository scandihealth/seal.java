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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/SOSIFactory.java $
 * $Id: SOSIFactory.java 20824 2014-12-18 15:00:40Z ChristianGasser $
 */
package dk.sosi.seal;

import dk.sosi.seal.model.*;
import dk.sosi.seal.model.constants.DGWSConstants;
import dk.sosi.seal.modelbuilders.*;
import dk.sosi.seal.pki.*;
import dk.sosi.seal.pki.impl.PropertiesSOSIConfiguration;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import dk.sosi.seal.xml.XmlUtilException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

/**
 * The "factory" used to construct realizations of the SOSI abstractions in the
 * seal component. The factory acts as the entrypoint in the component, and on
 * it, you will find factory methods for nearly all types in the SOSI component.
 *
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class SOSIFactory {

	//TODO change properties names to include packages instead of "sosi:"
	public static final String PROPERTYNAME_SOSI_VALIDATE = "sosi:validate";
	public static final String PROPERTYNAME_SOSI_ISSUER = "sosi:issuer";
	public static final String PROPERTYNAME_SOSI_ROOTSCHEMA = "sosi:rootschema";
	public static final String PROPERTYNAME_SOSI_FEDERATION_AUDITHANDLER = "sosi:federation.audithandler";
	public static final String PROPERTYNAME_SOSI_CRYPTOPROVIDER_PKCS12 = "sosi:cryptoprovider.pkcs12";
	public static final String PROPERTYNAME_SOSI_CRYPTOPROVIDER_RSA = "sosi:cryptoprovider.rsa";
	public static final String PROPERTYNAME_SOSI_CRYPTOPROVIDER_SHA1WITHRSA = "sosi:cryptoprovider.sha1withrsa";
	public static final String PROPERTYNAME_SOSI_CRYPTOPROVIDER_X509 = "sosi:cryptoprovider.x509";
	public static final String PROPERTYNAME_SOSI_CRYPTOFACADE_CERTIFICATE_REQUEST_HANDLER = "sosi:cryptofacade.certificaterequesthandler";
	public static final String PROPERTYVALUE_SOSI_CRYPTOPROVIDER_BOUNCYCASTLE = "BC";
	public static final String PROPERTYVALUE_SOSI_CRYPTOFACADE_BC_CERTIFICATE_REQUEST_HANDLER = "dk.sosi.seal.security.BCCertificateRequestHandler";
	public static final String SOSI_DEFAULT_AUDIT_EVENT_HANDLER = "dk.sosi.seal.pki.NoAuditEventHandler";

    @Deprecated
    public static final String PROPERTYNAME_SOSI_LDAP_CERTIFICATE_HOST_OCES1 = "sosi:federationcertificate.host.oces1";
    @Deprecated
    public static final String PROPERTYNAME_SOSI_LDAP_CERTIFICATE_PORT_OCES1 = "sosi:federationcertificate.port.oces1";

    public static final String PROPERTYNAME_SOSI_LDAP_CERTIFICATE_HOST_OCES2 = "sosi:federationcertificate.host.oces2";
    public static final String PROPERTYNAME_SOSI_LDAP_CERTIFICATE_PORT_OCES2 = "sosi:federationcertificate.port.oces2";

	/** Cache the DOM <code>DocumentBuilderFactory</code>. Please note that this constitutes a JEE compliance problem. Set to <code>false</code> if this is a problem */
	public static final String PROPERTYNAME_SOSI_USE_DOCUMENT_BUILDER_FACTORY_CACHE  = "sosi:useDBFCache";
	public static final String PROPERTYVALUE_SOSI_USE_DOCUMENT_BUILDER_FACTORY_CACHE  = "true";

    // enhanced validation against specialized schemas
    public static final String PROPERTYNAME_SOSI_VALIDATE_ENHANCED = "sosi:validate.enhanced";
    public static final String PROPERTYVALUE_SOSI_VALIDATE_ENHANCED = "true";

	// DGWS version - currently 1.0 and 1.0.1 are supported
    public static final String PROPERTYNAME_SOSI_DGWS_VERSION = "sosi:dgws.version";
    public static final String SOSI_DEFAULT_DGWS_VERSION = DGWSConstants.VERSION_1_0_1;

    // Seal (Not DGWS) message version - currently [1.0_0,1.0_1,1.0_2] supported
    public static final String PROPERTYNAME_SOSI_SEAL_MESSAGE_VERSION = "sosi:seal.msg.version";
    public static final String PROPERTYVALUE_SOSI_SEAL_MESSAGE_VERSION = "1.0_0";

    public static final String PROPERTYNAME_SOSI_DO_NOT_REGISTER_STR_TRANSFORM = "sosi:do.not.register.STRTransform";

    public static final String PROPERTYNAME_SOSI_CHECK_TRUST_FOR_SECURITY_TOKEN_RESPONSE = "sosi:check.trust.SecurityTokenResponse";

	private Federation federation;
    private SignatureProvider signatureProvider;
	private Properties properties;

    /**
     * <p>
     * Creates a <code>SOSIFactory</code> instance given a
     * <code>SignatureProvider</code> and a <code>Federation</code>.
     * </p>
     *
     * @param federation
     *            The <code>Federation</code> to embed in this factory
     *            instance.
     * @param provider
     *            The <code>SignatureProvider</code> to embed in this factory
     *            instance.
     * @param properties
     *            A set of properties containing configuration values for the
     *            SOSI library.
     */
    public SOSIFactory(Federation federation, SignatureProvider provider, Properties properties) throws ModelException {
        super();
        this.federation = federation;
        if (provider == null) {
            throw new ModelException("You cannot construct a SOSIFactory without SignatureProvider");
        }
        initialize(provider, properties);
    }

    /**
     * <p>
     * Creates a <code>SOSIFactory</code> instance given a
     * <code>CredentialVault</code> and a <code>Federation</code>.
     * </p>
     * 
     * @param federation
     *            The <code>Federation</code> to embed in this factory
     *            instance.
     * @param credentialVault
     *            The <code>CredentialVault</code> to embed in this factory
     *            instance.
     * @param properties
     *            A set of properties containing configuration values for the
     *            SOSI library.
     */
    public SOSIFactory(Federation federation, CredentialVault credentialVault, Properties properties) throws ModelException {
        super();
        this.federation = federation;
        if (credentialVault == null) {
            throw new ModelException("The SOSI factory must have a CredentialVault instance");
        }
        initialize(SignatureProviderFactory.fromCredentialVault(credentialVault, properties), properties);
    }

	/**
	 * <p>
	 * Creates a <code>SOSIFactory</code> instance given a
	 * <code>CredentialVault</code>.
	 * </p>
	 *
	 * @param credentialVault
	 *            The <code>CredentialVault</code> to embed in this factory
	 *            instance.
	 * @param properties
	 *            A set of properties containing configuration values for the
	 *            SOSI library.
	 */
	public SOSIFactory(CredentialVault credentialVault, Properties properties) throws ModelException {
	    this(null, credentialVault, properties);
	}

	private void initialize(SignatureProvider provider, Properties props) throws ModelException {
        if (props == null) {
            throw new ModelException("You cannot construct a SOSIFactory without properties");
        }
        this.signatureProvider = provider;
        this.properties = props;
    }

	/**
	 * Returns the federation associated to this credential vault.
	 */
	public Federation getFederation() {
		return federation;
	}


	/**
	 * Returns the associated credential vault or null if this SOSIFactory
     * was constructed without CredentialVault or CredentialVault-based SignatureProvider.
	 */
	public CredentialVault getCredentialVault() {
        if (signatureProvider instanceof CredentialVaultSignatureProvider) {
            return ((CredentialVaultSignatureProvider) signatureProvider).getCredentialVault();
        } else {
            return null;
        }
    }

    /**
     * Returns the associated signature provider.
     */
    public SignatureProvider getSignatureProvider() {
        return signatureProvider;
    }

    /**
	 * Returns the properties for the SOSI library.
	 */
	public Properties getProperties() {
		return properties;
	}

	/**
	 * Constructs a <code>Request</code> model instance.
	 * <p/>
	 * After the object has been created, and an <code>IDCard</code> has been
	 * associated with the request, the request can be <i>"serialized"</i> into XML
	 * (or more precisely a DOM representation) by calling the <code>serialize2DOMDocument()</code> method.
	 *
	 * @param demandNonRepudiationReceipt If <code>true</code> this request demands a digital signature on the response to this request.
	 * @param flowID                      an optional "session" or "workflow" ID. If the value is <code>null</code> is
	 *                                    the <code>flowID</code> will get the same value as <code>messageID</code>.
	 */
	public Request createNewRequest(boolean demandNonRepudiationReceipt, String flowID) {
		return new Request(getDGWSVersion(), demandNonRepudiationReceipt, flowID, this);
	}

	/**
	 * Constructs a <code>SecurityTokenRequest</code> model instance. <p/>
	 * After the object has been created, and an <code>IDCard</code> has been
	 * associated with the request, the request can be <i>"serialized"</i> into
	 * XML (or more precisely a DOM representation) by calling the
	 * <code>getDOMDocument()</code> method.
	 *
	 */
	public SecurityTokenRequest createNewSecurityTokenRequest() {
		return new SecurityTokenRequest(getDGWSVersion(), this);
	}

	/**
	 * Creates a <code>SecurityTokenResponse</code> model element for a
	 * positive SecurityTokenResponse. Per default a
	 * <code>SecurityTokenResponse</code> is created as a response to a
	 * request. To enable protection against replay attacks, the response embeds
	 * the ID of the corresponding request (see the <code>inResponseToID</code>)
	 * which is actually a <i>nonce</i>. The request will also get its own
	 * federation unique message ID (also a nonce). <p/> After the object has
	 * been created, and an optional <code>IDCard</code> has been associated
	 * with the response, the response can be <i>"serialized"</i> into XML (or
	 * more precisely a DOM representation) by calling the
	 * <code>getDOMDocument()</code> method.
	 *
	 * @param request
	 * 			The request that this a response to
	 *
	 * @return A new SecurityTokenResponse for a positive response
	 */
	public SecurityTokenResponse createNewSecurityTokenResponse(SecurityTokenRequest request) {
		return createNewSecurityTokenResponse(request.getDGWSVersion(), request.getMessageID());
	}

	/**
	 * Creates a <code>SecurityTokenResponse</code> model element for a
	 * positive SecurityTokenResponse. Per default a
	 * <code>SecurityTokenResponse</code> is created as a response to a
	 * request. To enable protection against replay attacks, the response embeds
	 * the ID of the corresponding request (see the <code>inResponseToID</code>)
	 * which is actually a <i>nonce</i>. The request will also get its own
	 * federation unique message ID (also a nonce). <p/> After the object has
	 * been created, and an optional <code>IDCard</code> has been associated
	 * with the response, the response can be <i>"serialized"</i> into XML (or
	 * more precisely a DOM representation) by calling the
	 * <code>getDOMDocument()</code> method.
	 *
	 * @param dgwsVersion
	 * 			  The DGWS version to use for this message
	 * @param inResponseToID
	 * 			The messageID of the request that this error is in response to
	 *
	 * @return A new SecurityTokenResponse for a positive response
	 */
	public SecurityTokenResponse createNewSecurityTokenResponse(String dgwsVersion, String inResponseToID) {
		return new SecurityTokenResponse(dgwsVersion, inResponseToID, this);
	}

	/**
	 * Creates a <code>Reply</code> model element for a negative Reply. Per
	 * default a <code>Reply</code> is created as a response to a request. To
	 * enable protection against replay attacks, the response embeds the ID of
	 * the corresponding request (see the <code>inResponseToID</code>) which
	 * is actually a <i>nonce</i>.
	 * <p/>
	 * The response can be <i>"serialized"</i> into XML (or more
	 * precisely a DOM representation) by calling the
	 * <code>getDOMDocument()</code> method.
	 * @param request
	 * 			The request that this a response to
	 * @param faultCode
	 *            The status code from FaultCodeValues
	 * @param faultString
	 *            A human readable error text
	 * @param faultActor
	 *            The "actor" who is sending the fault, for instance <code>http://www.sosi.dk/STS</code>
	 * @return A new SecurityTokenResponse for a negative response
	 */
	public SecurityTokenResponse createNewSecurityTokenErrorResponse(SecurityTokenRequest request, String faultCode, String faultString, String faultActor) {
		return createNewSecurityTokenErrorResponse(request.getDGWSVersion(), request.getMessageID(), faultCode, faultString, faultActor);
	}

	/**
	 * Creates a <code>Reply</code> model element for a negative Reply. Per
	 * default a <code>Reply</code> is created as a response to a request. To
	 * enable protection against replay attacks, the response embeds the ID of
	 * the corresponding request (see the <code>inResponseToID</code>) which
	 * is actually a <i>nonce</i>.
	 * <p/>
	 * The response can be <i>"serialized"</i> into XML (or more
	 * precisely a DOM representation) by calling the
	 * <code>getDOMDocument()</code> method.
	 * @param dgwsVersion
	 * 			  The DGWS version to use for this message
	 * @param inResponseToID
	 * 			The messageID of the request that this error is in response to
	 * @param faultCode
	 *            The status code from FaultCodeValues
	 * @param faultString
	 *            A human readable error text
	 * @param faultActor
	 *            The "actor" who is sending the fault, for instance <code>http://www.sosi.dk/STS</code>
	 *
	 * @return A new SecurityTokenResponse for a negative response
	 */
	public SecurityTokenResponse createNewSecurityTokenErrorResponse(String dgwsVersion, String inResponseToID, String faultCode, String faultString, String faultActor) {
		return new SecurityTokenResponse(dgwsVersion, inResponseToID, faultCode, faultString, faultActor, this);
	}

	/**
	 * Creates a <code>Reply</code> model element for a positive Reply. Per
	 * default a <code>Reply</code> is created as a response to a request. To
	 * enable protection against replay attacks, the response embeds the ID of
	 * the corresponding request (see the <code>inResponseToID</code>) which
	 * is actually a <i>nonce</i>. The request will also get its own federation
	 * unique message ID (also a nonce). <p/> After the object has been created,
	 * and an optional <code>IDCard</code> has been associated with the
	 * response, the response can be <i>"serialized"</i> into XML (or more
	 * precisely a DOM representation) by calling the
	 * <code>getDOMDocument()</code> method.
	 *
	 * @param request
	 * 			The request that this a response to
	 * @param flowStatus
	 *            The status code from FlowStatusValues
	 * @return A new Reply for a positive response
	 */
	public Reply createNewReply(Request request, String flowStatus) {
		return new Reply(request.getDGWSVersion(), request.getMessageID(), request.getFlowID(), flowStatus, this);
	}

	/**
	 * Creates a <code>Reply</code> model element for a positive Reply. Per
	 * default a <code>Reply</code> is created as a response to a request. To
	 * enable protection against replay attacks, the response embeds the ID of
	 * the corresponding request (see the <code>inResponseToID</code>) which
	 * is actually a <i>nonce</i>. The request will also get its own federation
	 * unique message ID (also a nonce). <p/> After the object has been created,
	 * and an optional <code>IDCard</code> has been associated with the
	 * response, the response can be <i>"serialized"</i> into XML (or more
	 * precisely a DOM representation) by calling the
	 * <code>getDOMDocument()</code> method.
	 *
	 * @param dgwsVersion
	 *            The DGWS version of this
	 * @param inResponseToID
	 *            The ID of the request that this instance is a reponse to.
	 * @param flowID
	 *            an optional "session" or "workflow" ID. If the value is
	 *            <code>null</code> is the <code>flowID</code> will get the
	 *            same value as <code>messageID</code>. For replies the
	 *            <code>flowID</code> is usually taken from the corresponding
	 *            request.
	 * @param flowStatus
	 *            The status code from FlowStatusValues
	 * @return A new Reply for a positive response
	 */
	public Reply createNewReply(String dgwsVersion, String inResponseToID, String flowID, String flowStatus) {
		return new Reply(dgwsVersion, inResponseToID, flowID, flowStatus, this);
	}

	/**
	 * Creates a <code>Reply</code> model element for a negative Reply. Per
	 * default a <code>Reply</code> is created as a response to a request. To
	 * enable protection against replay attacks, the response embeds the ID of
	 * the corresponding request (see the <code>inResponseToID</code>) which
	 * is actually a <i>nonce</i>. The request will also get its own federation
	 * unique message ID (also a nonce). <p/> After the object has been created,
	 * and an optional <code>IDCard</code> has been associated with the
	 * response, the response can be <i>"serialized"</i> into XML (or more
	 * precisely a DOM representation) by calling the
	 * <code>getDOMDocument()</code> method.
	 *
	 * @param dgwsVersion
	 * 			  The DGWS version to use for this message
	 * @param inResponseToID
	 *            The ID of the request that this instance is a reponse to.
	 * @param flowID
	 *            an optional "session" or "workflow" ID. If the value is
	 *            <code>null</code> is the <code>flowID</code> will get the
	 *            same value as <code>messageID</code>. For replies the
	 *            <code>flowID</code> is usually taken from the corresponding
	 *            request.
	 * @param faultCode
	 *            The status code from FaultCodeValues
	 * @param faultString
	 *            A human readable error text
	 * @return A new Reply for a negative response
	 */
	public Reply createNewErrorReply(String dgwsVersion, String inResponseToID, String flowID, String faultCode, String faultString) {
		return createNewErrorReply(dgwsVersion, inResponseToID, flowID, faultCode, faultString, null);
	}

    /**
     * Creates a <code>Reply</code> model element for a negative Reply. Per
     * default a <code>Reply</code> is created as a response to a request. To
     * enable protection against replay attacks, the response embeds the ID of
     * the corresponding request (see the <code>inResponseToID</code>) which
     * is actually a <i>nonce</i>. The request will also get its own federation
     * unique message ID (also a nonce). <p/> After the object has been created,
     * and an optional <code>IDCard</code> has been associated with the
     * response, the response can be <i>"serialized"</i> into XML (or more
     * precisely a DOM representation) by calling the
     * <code>getDOMDocument()</code> method.
     *
     * @param dgwsVersion
     * 			  The DGWS version to use for this message
     * @param inResponseToID
     *            The ID of the request that this instance is a reponse to.
     * @param flowID
     *            an optional "session" or "workflow" ID. If the value is
     *            <code>null</code> is the <code>flowID</code> will get the
     *            same value as <code>messageID</code>. For replies the
     *            <code>flowID</code> is usually taken from the corresponding
     *            request.
     * @param faultCode
     *            The status code from FaultCodeValues
     * @param faultString
     *            A human readable error text
     * @param extraFaultDetails
     *            A list of <code>org.w3c.dom.Element</code> to include as extra
     *            elements under the generated soap faults 'detail' element
     * @return A new Reply for a negative response
     */
    public Reply createNewErrorReply(String dgwsVersion, String inResponseToID, String flowID, String faultCode, String faultString, List<Element> extraFaultDetails) {
        return new Reply(dgwsVersion, inResponseToID, flowID, faultCode, faultString, this, extraFaultDetails);
    }

    /**
	 * Creates a <code>Reply</code> model element for a negative Reply. Per
	 * default a <code>Reply</code> is created as a response to a request. To
	 * enable protection against replay attacks, the response embeds the ID of
	 * the corresponding request (see the <code>inResponseToID</code>) which
	 * is actually a <i>nonce</i>. The request will also get its own federation
	 * unique message ID (also a nonce). <p/> After the object has been created,
	 * and an optional <code>IDCard</code> has been associated with the
	 * response, the response can be <i>"serialized"</i> into XML (or more
	 * precisely a DOM representation) by calling the
	 * <code>getDOMDocument()</code> method.
	 *
	 * @param request
	 * 			The request that this an error reply to
	 * @param faultCode
	 *            The status code from FaultCodeValues
	 * @param faultString
	 *            A human readable error text
	 * @return A new Reply for a negative response
	 */
	public Reply createNewErrorReply(Request request, String faultCode, String faultString) {
		return createNewErrorReply(request.getDGWSVersion(), request.getMessageID(), request.getFlowID(), faultCode, faultString);
	}

    /**
     * Creates a <code>Reply</code> model element for a negative Reply. Per
     * default a <code>Reply</code> is created as a response to a request. To
     * enable protection against replay attacks, the response embeds the ID of
     * the corresponding request (see the <code>inResponseToID</code>) which
     * is actually a <i>nonce</i>. The request will also get its own federation
     * unique message ID (also a nonce). <p/> After the object has been created,
     * and an optional <code>IDCard</code> has been associated with the
     * response, the response can be <i>"serialized"</i> into XML (or more
     * precisely a DOM representation) by calling the
     * <code>getDOMDocument()</code> method.
     *
     * @param request
     * 			The request that this an error reply to
     * @param faultCode
     *            The status code from FaultCodeValues
     * @param faultString
     *            A human readable error text
     * @param extraFaultDetails
     *            A list of <code>org.w3c.dom.Element</code> to include as extra
     *            elements under the generated soap faults 'detail' element
     * @return A new Reply for a negative response
     */
    public Reply createNewErrorReply(Request request, String faultCode, String faultString, List<Element> extraFaultDetails) {
        return createNewErrorReply(request.getDGWSVersion(), request.getMessageID(), request.getFlowID(), faultCode, faultString, extraFaultDetails);
    }

    /**
	 * Creates a new <code>SystemIDCard</code>.
	 *
	 * @param itSystemName
	 *            The IT system name to embed in the IDCard.
	 * @param careProvider
	 *            The organizational unit that the user is acting on behalf of
	 * @param authenticationLevel
	 *            The requested type of signature for this ID card (DGWS level 1 through 3). See @link{dk.sosi.seal.model.AuthenticationLevel}.
	 * @param certificate
	 *            The public certificate that can validate this ID-card
	 * @param alternativeIdentifier
     *            A <code>String</code> denoting an alternative identifier that
	 *            will be used as SAML Subject (of type medcom:other) when serializing
	 *            this IDCard instead. May be <code>null</null>.
	 * @deprecated
	 * 			  Use {@link #createNewSystemIDCard(String, CareProvider, AuthenticationLevel, String, String, X509Certificate, String)} instead
	 */
	@Deprecated
    public SystemIDCard createNewSystemIDCard(String itSystemName, CareProvider careProvider, AuthenticationLevel authenticationLevel, X509Certificate certificate,
			String alternativeIdentifier) {
		return createNewSystemIDCard(itSystemName, careProvider, authenticationLevel, null, null, certificate, alternativeIdentifier);
	}

	/**
	 * Creates a new <code>SystemIDCard</code>.
	 *
	 * @param itSystemName
	 *            The IT system name to embed in the IDCard.
	 * @param careProvider
	 *            The organizational unit that the user is acting on behalf of
	 * @param authenticationLevel
	 *            The requested type of signature for this ID card (DGWS level 1 through 3). See @link{dk.sosi.seal.model.AuthenticationLevel}.
	 * @param username
	 *            The username to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
	 * @param password
	 *            The password to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
	 * @param certificate
	 *            The public certificate that can validate this ID-card
	 * @param alternativeIdentifier
     *            A <code>String</code> denoting an alternative identifier that
	 *            will be used as SAML Subject (of type medcom:other) when serializing
	 *            this IDCard instead. May be <code>null</null>.
	 */
	public SystemIDCard createNewSystemIDCard(String itSystemName, CareProvider careProvider, AuthenticationLevel authenticationLevel, String username, String password,
			X509Certificate certificate, String alternativeIdentifier) {
		SystemInfo systemInfo = new SystemInfo(careProvider, itSystemName);
		return new SystemIDCard(getDGWSVersion(), authenticationLevel, getIssuer(), systemInfo, SignatureUtil.getDigestOfCertificate(certificate), alternativeIdentifier, username, password);
	}

	/**
	 * Creates a new <code>UserIDCard</code>.
	 *
	 * @param itSystemName
	 *            The IT system name to embed in the IDCard.
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
	 * @param careProvider
	 *            The organizational unit that the user is acting on behalf of
	 * @param authorizationCode
	 *            The authorization code for the user (SST)
	 * @param authenticationLevel
	 *            The requested type of signature for this ID card
	 * @param certificate
	 *            The public certificate that can validate this ID-card. May be <code>null</code>.
	 * @param alternativeIdentifier
     *            A <code>String</code> denoting an alternative identifier that
	 *            will be used as SAML Subject (of type medcom:other) when serializing
	 *            this IDCard instead. May be <code>null</null>.
	 * @deprecated
	 *            Use {@link #createNewUserIDCard(String, UserInfo, CareProvider, AuthenticationLevel, String, String, X509Certificate, String)} instead
	 */
	@Deprecated
    public UserIDCard createNewUserIDCard(String itSystemName, String cpr, String givenName, String surName, String email, String occupation, String role,
		CareProvider careProvider, String authorizationCode, AuthenticationLevel authenticationLevel, X509Certificate certificate, String alternativeIdentifier) {

		UserInfo userInfo = new UserInfo(cpr, givenName, surName, email, occupation, role, authorizationCode);
		return createNewUserIDCard(itSystemName, userInfo, careProvider, authenticationLevel, null, null, certificate, alternativeIdentifier);
	}

	/**
	 * Creates a new <code>UserIDCard</code>.
	 *
	 * @param itSystemName
	 *            The IT system name to embed in the IDCard.
	 * @param userInfo
	 *            A <code>UserInfo</code> instance representing the user
	 * @param careProvider
	 *            The organizational unit that the user is acting on behalf of
	 * @param authenticationLevel
	 *            The requested type of signature for this ID card
	 * @param username
	 *            The username to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
	 * @param password
	 *            The password to employ when creating an idcard with authenticationLeve 2. May be <code>null</code>.
	 * @param certificate
	 *            The public certificate that can validate this ID-card. May be <code>null</code>.
	 * @param alternativeIdentifier
     *            A <code>String</code> denoting an alternative identifier that
	 *            will be used as SAML Subject (of type medcom:other) when serializing
	 *            this IDCard instead. May be <code>null</null>.
	 */
	public UserIDCard createNewUserIDCard(String itSystemName, UserInfo userInfo, CareProvider careProvider, AuthenticationLevel authenticationLevel, String username,
			String password, X509Certificate certificate, String alternativeIdentifier) {

		SystemInfo systemInfo = new SystemInfo(careProvider, itSystemName);
		return new UserIDCard(getDGWSVersion(), authenticationLevel, getIssuer(), systemInfo, userInfo, SignatureUtil.getDigestOfCertificate(certificate), alternativeIdentifier, username, password);
	}

	/**
	 * Creates a new <code>IDCard</code> based on the data from an existing id
	 * card. The <code>IDCard</code> will get a new unique <code>id</code>
	 * and will have the same authentication level as the original
	 * <code>IDCard</code>, but will always get signed with a VOCES
	 * signature, making this method ideal for <code>IDCard</code> issuing
	 * libraries like IdP's.
	 *
	 * @param origCard
	 *            the id card to copy data from
	 * @param cpr
	 *            cpr to add if origCard doesnt contain it
	 * @return a new <code>UserIDCard</code> if the original id card was a
	 *         <code>UserIDCard</code> or a new <code>SystemIDCard</code> if
	 *         the original id card was a <code>SystemIDCard</code>.
     *
     * @deprecated Use one of the methods taking a specific type of IDCard instead
	 */
	@Deprecated
    public IDCard copyToVOCESSignedIDCard(IDCard origCard, String cpr) {
		if (origCard instanceof UserIDCard) {
            UserIDCard userIdCard = (UserIDCard) origCard;
            final UserInfo userInfo;
            if(cpr == null || "".equals(cpr))
                userInfo = userIdCard.getUserInfo();
            else {
                userInfo = new UserInfo(userIdCard.getUserInfo(), cpr);
            }
            return copyToVOCESSignedIdCard(userIdCard, userInfo);
        } else if (origCard instanceof SystemIDCard) {
            return copyToVOCESSignedIdCard((SystemIDCard) origCard, false);
        } else {
			throw new ModelException("Unknown IDCard type");
		}
	}

    /**
     * Creates a new <code>IDCard</code> based on the data from an existing id
     * card. The <code>IDCard</code> will get a new unique <code>id</code>
     * and will have the same authentication level as the original
     * <code>IDCard</code>, but will always get signed with a VOCES
     * signature, making this method ideal for <code>IDCard</code> issuing
     * libraries like IdP's.
     *
     * @param origCard
     *            the id card to copy data from
     * @return a new <code>UserIDCard</code> if the original id card was a
     *         <code>UserIDCard</code> or a new <code>SystemIDCard</code> if
     *         the original id card was a <code>SystemIDCard</code>.
     */
    public IDCard copyToVOCESSignedIDCard(IDCard origCard) {
        return copyToVOCESSignedIDCard(origCard, false);
    }

    public IDCard copyToVOCESSignedIDCard(IDCard origCard, boolean setCertAttributesAsSubjectNameID) {
        if (origCard instanceof UserIDCard) {
            UserIDCard userIdCard = (UserIDCard) origCard;
            return copyToVOCESSignedIdCard(userIdCard, userIdCard.getUserInfo(), setCertAttributesAsSubjectNameID);
        } else if (origCard instanceof SystemIDCard) {
            return copyToVOCESSignedIdCard((SystemIDCard) origCard, setCertAttributesAsSubjectNameID);
        } else {
            throw new ModelException("Unknown IDCard type");
        }
    }

    /**
     * Creates a new <code>UserIDCard</code> based on the data from an existing id
     * card. The <code>IDCard</code> will get a new unique <code>id</code>
     * and will have the same authentication level as the original
     * <code>IDCard</code>, but will always get signed with a VOCES
     * signature, making this method ideal for <code>IDCard</code> issuing
     * libraries like IdP's.
     *
     * @param origUserIdCard
     *            the id card to copy data from
     * @param newUserInfo
     *            UserInfo to insert instead of the original
     * @return a new <code>UserIDCard</code>.
     */
    public IDCard copyToVOCESSignedIdCard(UserIDCard origUserIdCard, UserInfo newUserInfo) {
        return copyToVOCESSignedIdCard(origUserIdCard, newUserInfo, false);
    }

    public IDCard copyToVOCESSignedIdCard(UserIDCard origUserIdCard, UserInfo newUserInfo, boolean setCertAttributesAsSubjectNameID) {
        // if no certHash exists on origCard, generate new on copy
        String certHash = getOrGenerateCertHash(origUserIdCard);
        String alternativeIdentifier = setCertAttributesAsSubjectNameID ? constructCertAttributes(origUserIdCard.getSignedByCertificate()) : null;
        IDCard result = new UserIDCard(origUserIdCard, getIssuer(), newUserInfo, certHash, alternativeIdentifier);
        return getSignedIdCard(result);
    }

    private String constructCertAttributes(X509Certificate signedByCertificate) {
        return new CertificateInfo(signedByCertificate).toString();
    }

    /**
     * Creates a new <code>UserIDCard</code> based on the data from an existing id
     * card. The <code>IDCard</code> will get a new unique <code>id</code>
     * and will have the same authentication level as the original
     * <code>IDCard</code>, but will always get signed with a VOCES
     * signature, making this method ideal for <code>IDCard</code> issuing
     * libraries like IdP's.
     *
     *
     * @param origSystemIdCard
     *            the id card to copy data from
     * @param setCertAttributesAsSubjectNameID
     * @return a new <code>UserIDCard</code>.
     */
    private IDCard copyToVOCESSignedIdCard(SystemIDCard origSystemIdCard, boolean setCertAttributesAsSubjectNameID) {
        // if no certHash exists on origCard, generate new on copy
        String certHash = getOrGenerateCertHash(origSystemIdCard);
        String alternativeIdentifier = setCertAttributesAsSubjectNameID ? constructCertAttributes(origSystemIdCard.getSignedByCertificate()) : null;
        IDCard result = new SystemIDCard(origSystemIdCard, getIssuer(), certHash, alternativeIdentifier);
        return getSignedIdCard(result);
    }

    private String getOrGenerateCertHash(IDCard origCard) {
        if (origCard.getCertHash() == null || "".equals(origCard.getCertHash())) {
            return origCard.generateCertHash();
        } else {
            return origCard.getCertHash();
        }
    }

    private IDCard getSignedIdCard(IDCard result) {
        Request tmp = createNewRequest(false, "");
        tmp.setIDCard(result);
        Document doc = tmp.serialize2DOMDocument();
        result.sign(doc, signatureProvider);
        return tmp.getIDCard();
    }

    /**
	 * "Deserializes" an XML document into a <code>Request</code> model
	 * object.
	 *
	 * @param xml
	 *            The XML to deserialize.
	 * @throws XmlUtilException
	 *             Thrown if the XML could not be read and schema-validated.
	 * @throws ModelBuildException
	 *             Thrown if the model builder was not able to deserialize the
	 *             XML.
	 */
	public Request deserializeRequest(String xml) throws XmlUtilException, ModelBuildException {
		RequestModelBuilder b = new RequestModelBuilder(this);
		return b.buildModel(XmlUtil.readXml(properties, xml, validate()));
	}

	/**
	 * "Deserializes" an XML document into a <code>Reply</code> model object.
	 *
	 * @param xml
	 *            The XML to deserialize.
	 * @throws XmlUtilException
	 *             Thrown if the XML could not be read and schema-validated.
	 * @throws ModelBuildException
	 *             Thrown if the model builder was not able to deserialize the
	 *             XML.
	 */
	public Reply deserializeReply(String xml) throws XmlUtilException, ModelBuildException {
		ReplyModelBuilder b = new ReplyModelBuilder(this);
		return b.buildModel(XmlUtil.readXml(properties, xml, validate()));
	}

	/**
	 * "Deserializes" an XML document into a <code>SecurityTokenRequest</code>
	 * model object.
	 *
	 * @param xml
	 *            The XML to deserialize.
	 * @throws XmlUtilException
	 *             Thrown if the XML could not be read and schema-validated.
	 * @throws ModelBuildException
	 *             Thrown if the model builder was not able to deserialize the
	 *             XML.
	 */
	public SecurityTokenRequest deserializeSecurityTokenRequest(String xml) throws XmlUtilException, ModelBuildException {
		SecurityTokenRequestModelBuilder b = new SecurityTokenRequestModelBuilder(this);
		return b.buildModel(XmlUtil.readXml(properties, xml, validate()));
	}

	/**
	 * "Deserializes" an XML document into a <code>Reply</code> model object.
	 *
	 * @param xml
	 *            The XML to deserialize.
	 * @throws XmlUtilException
	 *             Thrown if the XML could not be read and schema-validated.
	 * @throws ModelBuildException
	 *             Thrown if the model builder was not able to deserialize the
	 *             XML.
	 */
	public SecurityTokenResponse deserializeSecurityTokenResponse(String xml) throws XmlUtilException, ModelBuildException {
        boolean checkTrust = Boolean.getBoolean(PROPERTYNAME_SOSI_CHECK_TRUST_FOR_SECURITY_TOKEN_RESPONSE);
		SecurityTokenResponseModelBuilder b = new SecurityTokenResponseModelBuilder(this, checkTrust);
		return b.buildModel(XmlUtil.readXml(properties, xml, validate()));
	}


	/**
	 * "Deserializes" an XML document into an <code>IDCard</code> model object.
	 *
	 * @param xml
	 *            The XML to deserialize.
	 * @throws XmlUtilException
	 *             Thrown if the XML could not be read and schema-validated.
	 * @throws ModelBuildException
	 *             Thrown if the model builder was not able to deserialize the
	 *             XML.
	 */
	public IDCard deserializeIDCard(String xml) throws XmlUtilException, ModelBuildException {
		IDCardModelBuilder builder = new IDCardModelBuilder();
		return builder.buildModel(XmlUtil.readXml(properties, xml, validate()));
	}

	/**
	 * "Deserializes" an XML document into a <code>RequestHeader</code> model object.
	 *
	 * @param xml
	 *            The XML to deserialize.
	 * @throws XmlUtilException
	 *             Thrown if the XML could not be read and schema-validated.
	 * @throws ModelBuildException
	 *             Thrown if the model builder was not able to deserialize the
	 *             XML.
	 *
	 * @since 1.5.10
	 */
	public RequestHeader deserializeRequestHeader(String xml)  throws XmlUtilException, ModelBuildException {
		RequestHeaderModelBuilder builder = new RequestHeaderModelBuilder(this);
		return builder.buildModel(XmlUtil.readXml(properties, xml, validate()));
	}

	/**
	 * "Deserializes" an XML document into a <code>ReplyHeader</code> model object.
	 *
	 * @param xml
	 *            The XML to deserialize.
	 * @throws XmlUtilException
	 *             Thrown if the XML could not be read and schema-validated.
	 * @throws ModelBuildException
	 *             Thrown if the model builder was not able to deserialize the
	 *             XML.
	 *
	 * @since 1.5.10
	 */
	public ReplyHeader deserializeReplyHeader(String xml)  throws XmlUtilException, ModelBuildException {
		ReplyHeaderModelBuilder builder = new ReplyHeaderModelBuilder(this);
		return builder.buildModel(XmlUtil.readXml(properties, xml, validate()));
	}

	public static AuditEventHandler getAuditEventHandler(Properties properties) throws ModelException {
        // TODO: the configuration created should probably be stored to avoid recreating it every time.
        return new PropertiesSOSIConfiguration(properties).getAuditEventHandler();
	}

    public String getIssuer() {
        return properties.getProperty(PROPERTYNAME_SOSI_ISSUER, "TheSOSILibrary");
    }

    // ==================================
    // Private methods
    // ==================================

	private boolean validate() {
		return properties.getProperty(PROPERTYNAME_SOSI_VALIDATE, "true").equalsIgnoreCase("true");
	}

	private String getDGWSVersion() {
		return properties.getProperty(PROPERTYNAME_SOSI_DGWS_VERSION, SOSI_DEFAULT_DGWS_VERSION);
	}
}