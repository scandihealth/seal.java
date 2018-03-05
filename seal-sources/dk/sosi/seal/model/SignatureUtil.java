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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/SignatureUtil.java $
 * $Id: SignatureUtil.java 20767 2014-12-10 15:12:04Z ChristianGasser $
 */
package dk.sosi.seal.model;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.constants.*;
import dk.sosi.seal.modelbuilders.SignatureInvalidModelBuildException;
import dk.sosi.seal.pki.*;
import dk.sosi.seal.transform.internal.STRTransform;
import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.vault.CredentialVaultException;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSDocInfoStore;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.*;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Utility class for creating and validating XML Digital Signatures
 *
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class SignatureUtil {

	// used for testing - we need to be sure BC isnt installed in java.security
	static final boolean bcAddedInJavaSecurity = Security.getProvider(SOSIFactory.PROPERTYVALUE_SOSI_CRYPTOPROVIDER_BOUNCYCASTLE) != null; //NOPMD

    static {
        // Initialize the Apache XML Signature API
        org.apache.xml.security.Init.init();
        if (! Boolean.getBoolean(SOSIFactory.PROPERTYNAME_SOSI_DO_NOT_REGISTER_STR_TRANSFORM)) {
            try {
                Transform.register(STRTransform.implementedTransformURI, STRTransform.class.getName());
            } catch (AlgorithmAlreadyRegisteredException e) {
                throw new RuntimeException("Unable to register STR-Transform " + STRTransform.class.getName(), e);
            }
        }

        Logger.getLogger("org.apache.xml.security.signature.Reference").setLevel(Level.OFF);
	}

    // Temporary inner class - to be deleted along the deprecated method that uses it
    private static class CredentialPairAdapterVault implements CredentialVault {

        private final CredentialPair credentialPair;

        public CredentialPairAdapterVault(CredentialPair credentialPair) {
            this.credentialPair = credentialPair;
        }

        public boolean isTrustedCertificate(X509Certificate certificate) throws CredentialVaultException {
            throw new UnsupportedOperationException();
        }

        public CredentialPair getSystemCredentialPair() throws CredentialVaultException {
            return credentialPair;
        }

        public void setSystemCredentialPair(CredentialPair credentialPair) throws CredentialVaultException {
            throw new UnsupportedOperationException();
        }

        public KeyStore getKeyStore() {
            throw new UnsupportedOperationException();
        }
    }

    //Temporary inner class - to be deleted again when LDAP certificate references are no longer to be supported
    private static class CertificateFederation extends Federation {

        private final X509Certificate certificate;

        public CertificateFederation(X509Certificate certificate) {
            super(System.getProperties(), null);
            this.certificate = certificate;
        }

        @Override
        protected boolean subjectDistinguishedNameMatches(DistinguishedName subjectDistinguishedName) {
            return false;
        }

        @Override
        public X509Certificate getFederationCertificate(FederationCertificateReference reference) {
            return certificate;
        }
    }

    static List<Element> dereferenceSignedElements(Element signatureElement) {
        final NodeList references = signatureElement.getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.REFERENCE);
        final LinkedList<Element> elements = new LinkedList<Element>();
        for (int i = 0; i < references.getLength(); i++) {
            final Element reference = (Element) references.item(i);
            final String uri = reference.getAttribute(DSAttributes.URI);
            final Element element = (Element) XmlUtil.getElementByIdExtended(signatureElement.getOwnerDocument(), uri.substring(1)); // Strip '#'
            if (element != null) {
                elements.add(element);
            }
        }
        return elements;
    }

    /**
	 * Create a &lt;ds:SignedInfo&gt; element with the c14n hashes for the elements, pointed to by the ids in the referenceUris array in the supplied
	 * Document. This method is useful for situations where the actual signature will be created externally e.g. in the situation where an actual user
	 * has to be prompted. The actual signature can be computed by: <p/>
	 * <ol>
	 * <li>Encrypting the bytes with the private key of the user</li>
	 * <li>Base64 encoding the signed byte array</li>
	 * </ol>
	 * <p/>
	 *
	 * @param referenceUris
	 *            An array of ID values to sign
	 * @param doc
	 *            The document that contains IDs pointed to in referenceURIs
	 * @param signatureParentID
	 * @return A <code>String</code> containing the Base64 encoded SHA-1 digest of the c14n &lt;ds:SignedInfo&gt; element
     * @deprecated Use {@link #getSignedInfoBytes(org.w3c.dom.Document, SignatureConfiguration)} instead
	 */
	@Deprecated
	 public static byte[] getSignedInfoBytes(String[] referenceUris, Document doc, String signatureParentID) {
        SignatureConfiguration configuration = new SignatureConfiguration(referenceUris, signatureParentID, IDValues.id);
        return getSignedInfoBytes(doc, configuration);
	}

    public static byte[] getSignedInfoBytes(Document doc, SignatureConfiguration configuration) {
        XMLSignature xmlSignature = initXmlSignature(doc, configuration);

		try {
			xmlSignature.getSignedInfo().generateDigestValues();
		} catch (XMLSignatureException e) {
			throw new ModelException("Unable to digest values", e);
		}

		tidyXML(xmlSignature.getElement());

		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

		try {
			xmlSignature.getSignedInfo().signInOctectStream(new BufferedOutputStream(byteArrayOutputStream));
		} catch (XMLSecurityException e) {
			throw new ModelException("Unable to generate c14n of SignedInfo", e);
		}

		return byteArrayOutputStream.toByteArray();
    }

	/**
	 * Sign elements in the supplied Document, pointed to by the ids in the referenceUris array using the private key from the credentialPair and
	 * attaching the corresponding certificate. Signature is enveloped and stored with the signatureParentLocation element or after the root, if that
	 * variable is null. Keys are exepcted to be RSA, and digest will be SHA1. Canonicalization is fixed to C14N_OMIT_COMMENTS.
	 *
	 * @param referenceUris
	 *            An array of URIs referenceing id's in doc that will be signed. URIs MUST NOT be prepended with a #
	 * @param credentialPair
	 *            Certificate and corresponding private key used for signing
	 * @param doc
	 *            The document that contains elements to be signed
	 * @param signatureSiblingLocationID
	 *            The parent node that will hold the ds:Signature element that was generated.
     * @deprecated Use {@link #sign(dk.sosi.seal.pki.SignatureProvider, org.w3c.dom.Document, SignatureConfiguration)} instead
	 */
	@Deprecated
    public static void sign(String[] referenceUris, CredentialPair credentialPair, Document doc, String signatureSiblingLocationID) {
        SignatureConfiguration signatureConfiguration = new SignatureConfiguration(referenceUris, signatureSiblingLocationID, IDValues.id);
        CredentialVault vault = new CredentialPairAdapterVault(credentialPair);
        sign(SignatureProviderFactory.fromCredentialVault(vault), doc, signatureConfiguration);
	}
	

    /**
     * Sign elements in the supplied Document, pointed to by the ids in the referenceUris array using the private key from the credentialPair and
     * attaching the corresponding certificate. Signature is enveloped and stored with the signatureParentLocation element or after the root, if that
     * variable is null. Keys are exepcted to be RSA, and digest will be SHA1. Canonicalization is fixed to C14N_OMIT_COMMENTS.
     *
     * @param credentialPair
     *            Certificate and corresponding private key used for signing
     * @param doc
     *            The document that contains elements to be signed
     * @param configuration
     *          Configuration parameters for the Signature to be created
     * @deprecated Use {@link #sign(dk.sosi.seal.pki.SignatureProvider, org.w3c.dom.Document, SignatureConfiguration)} instead
	 */
	@Deprecated
	public static void sign(CredentialPair credentialPair, Document doc, SignatureConfiguration configuration) {
        CredentialVault vault = new CredentialPairAdapterVault(credentialPair);
        sign(SignatureProviderFactory.fromCredentialVault(vault), doc, configuration);
    }

    public static void sign(SignatureProvider provider, Document doc, SignatureConfiguration configuration) {
        WSDocInfo wsDocInfo = new WSDocInfo(doc);
        WSDocInfoStore.store(wsDocInfo);

        try {

            byte[] bytes = getSignedInfoBytes(doc, configuration);
            SignatureProvider.SignatureResult result = provider.sign(bytes);
            injectSignature(doc, result.getSignature(), configuration, result.getCertificate(), false);

        } finally {
            WSDocInfoStore.delete(wsDocInfo);
        }
    }

	/**
	 * Validate the supplied ds:signature node. The signature is assumed to be enveloped
	 *
	 * @param signatureToValidate
	 * @return true if the signature validates, false otherwise
	 * @throws ModelException
	 *             if the signature could not be validated for any reason
	 */
	public static boolean validate(Node signatureToValidate, Federation federation, CredentialVault vault, boolean checkTrust) {
		return internalValidate(signatureToValidate, federation, vault, checkTrust);
	}

	/**
	 * Get the X509Certificate that is embedded within the supplied signatureElement
	 *
	 * @param signatureElement
	 *            &lt;ds:Signature&gt; which has an X509Certificate in it.
	 * @return The certificate
	 * @throws ModelException
	 *             if the X509Certificate could not be found or decoding failed
	 */
	public static X509Certificate getCertificateFromSignature(Node signatureElement) throws ModelException {
		NodeList nodeList = ((Element) signatureElement).getElementsByTagNameNS(NameSpaces.DSIG_SCHEMA, DSTags.X509CERTIFICATE);
		Node x509Certificate = nodeList.getLength() > 0 ? nodeList.item(0) : null;

		if (x509Certificate == null) {
			throw new ModelException("No " + NameSpaces.DSIG_SCHEMA + ":" + DSTags.X509CERTIFICATE + " element in signature " + signatureElement);
		}
		String certValue = XmlUtil.getTextNodeValue(x509Certificate);
		// strip whitespace
		certValue = certValue.replaceAll("\\s", "");
		byte[] base64decodedCertValue = XmlUtil.fromBase64(certValue);
        return CertificateParser.asCertificate(base64decodedCertValue);

    }

	/**
	 * Create a digest of the supplied certificate using SHA-1. If the passed certificate is <code>null</code> this methods returns
	 * <code>null</code>.
	 *
	 * @param certificate
	 *            The certificate to hash
	 * @return A base64 encoded string representing the hash
	 * @throws ModelException
	 *             If certificate is invalid or digesting failed
	 */
	public static String getDigestOfCertificate(X509Certificate certificate) throws ModelException {

		if (certificate == null)
			return null; // NOPMD
		byte[] certAsBytes;
		try {
			certAsBytes = certificate.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new ModelException("Unable to convert certificate to byte array", e);
		}

		byte[] hash = XmlUtil.getSha1Digest(certAsBytes);

		return XmlUtil.toBase64(hash);
	}

	/**
	 * Injects an externally created signature into the document.
	 *
	 * @param document
	 *            The document to inject into
	 * @param signature
	 *            The signature value (base 64 encoded)
	 * @param signatureParentElementID
	 *            The ID of the signature element
	 * @param certificate
	 *            The certificate used to create the signature
     * @deprecated Use {@link #injectSignature(org.w3c.dom.Document, String, SignatureConfiguration, java.security.cert.X509Certificate, boolean)} instead
	 */
	@Deprecated
	public static void injectSignature(Document document, String signature, String signatureParentElementID, X509Certificate certificate) {
        SignatureConfiguration configuration = new SignatureConfiguration((SignatureConfiguration.Reference[]) null, signatureParentElementID, null);
        injectSignature(document, signature, configuration, certificate, true);
	}

    public static void injectSignature(Document document, String signature, SignatureConfiguration configuration, X509Certificate certificate, boolean validateSignature) {
        if (certificate == null) {
            throw new ModelException("X509Certifcate cannot be <null>");
        }

        Element signatureParentElement = (Element) XmlUtil.getElementByIdExtended(document, configuration.getSignatureParentID());

        List<Element> signatureElements = XmlUtil.getChildElementsNS(signatureParentElement, NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE);
        if (signatureElements.size() != 1) {
            throw new ModelException("Expected 1 but found " + signatureElements.size() + " Signature elements");
        }
        Element elmSignature = signatureElements.get(0);

        List<Element> signatureValueElements = XmlUtil.getChildElementsNS(elmSignature, NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE_VALUE);
        if (signatureValueElements.size() != 1) {
            throw new ModelException("Expected 1 but found " + signatureValueElements.size() + " SignatureValue elements");
        }
        signatureValueElements.get(0).appendChild(document.createTextNode(signature));

        addKeyInfo(signatureParentElement, configuration, certificate);

        // Validate the signature before return
        if (validateSignature && !internalValidateIgnoreTrust(elmSignature, new CertificateFederation(certificate))) {
            throw new ModelException("The signature does not validate with the supplied certificate. "
                    + "Either the signature or the certificate is wrong.");
        }
    }

	private static void addKeyInfo(Element signatureParentElement, SignatureConfiguration configuration, X509Certificate certificate) {
        Document doc = signatureParentElement.getOwnerDocument();

        List<Element> signatureElements = XmlUtil.getChildElementsNS(signatureParentElement, NameSpaces.DSIG_SCHEMA, DSTags.SIGNATURE);
        if (signatureElements.size() != 1) {
            throw new ModelException("Expected 1 but found " + signatureElements.size() + " Signature elements");
        }
        Element elmSignature = signatureElements.get(0);


        Element elmKeyInfo = doc.createElementNS(NameSpaces.DSIG_SCHEMA, DSTags.KEY_INFO_PREFIXED);
        elmSignature.appendChild(elmKeyInfo);

        if (configuration.getKeyInfoId() != null) {
            elmKeyInfo.setAttributeNS(null, IDValues.Id, configuration.getKeyInfoId());
        }

        if (configuration.isAddCertificateAsReference()) {
            Element elmKeyName = doc.createElementNS(NameSpaces.DSIG_SCHEMA, DSTags.KEY_NAME_PREFIXED);
            elmKeyInfo.appendChild(elmKeyName);
            elmKeyName.setTextContent(new FederationCertificateReference(certificate).toString());
        } else {
            Element elmX509Data = doc.createElementNS(NameSpaces.DSIG_SCHEMA, DSTags.X509DATA_PREFIXED);
            elmKeyInfo.appendChild(elmX509Data);

            Element elmX509Certificate = doc.createElementNS(NameSpaces.DSIG_SCHEMA, DSTags.X509CERTIFICATE_PREFIXED);
            elmX509Data.appendChild(elmX509Certificate);

            String encodedCert;
            try {
                encodedCert = XmlUtil.toBase64(certificate.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new ModelException("Unable to encode certificate", e);
            }
            elmX509Certificate.appendChild(doc.createTextNode(encodedCert));
        }
    }

	public static void validateAllSignatures(Message message, NodeList signatures, Federation federation, CredentialVault credentialVault,
			boolean checkTrust) throws SignatureInvalidModelBuildException {

		for (int i = 0; i < signatures.getLength(); i++) {
			if (!SignatureUtil.validate(signatures.item(i), federation, credentialVault, checkTrust)) {

                Properties props = (federation == null) ? System.getProperties() : federation.getProperties();
				SOSIFactory.getAuditEventHandler(props).onInformationalAuditingEvent(
						AuditEventHandler.EVENT_TYPE_ERROR_VALIDATING_SOSI_MESSAGE,
						new Object[]{message}
						);
				throw new SignatureInvalidModelBuildException("Signature could not be validated", message.getMessageID(), message.getFlowID(), message.getDGWSVersion());
			}
		}
	}

	/**
	 * This method gets the Cryptoprovider even if properties is null. It defaults to the hardcoded value of
	 * SOSIFactory.PROPERTYVALUE_SOSI_CRYPTOPROVIDER_BOUNCYCASTLE
	 *
	 * It also adds org.bouncycastle.jce.provider.BouncyCastleProvider as provider if it is nessesary
	 *
	 * @param properties <code>Properties</code> to read from.
	 * @param key Key to read.
	 * @return The identified crypto provider key. 
	 */
	public static String getCryptoProvider(Properties properties, String key) {
		String cryptoProvider = SOSIFactory.PROPERTYVALUE_SOSI_CRYPTOPROVIDER_BOUNCYCASTLE;
		if (properties != null && properties.containsKey(key)){
			cryptoProvider = properties.getProperty(key);
		}
		if(cryptoProvider.equals(SOSIFactory.PROPERTYVALUE_SOSI_CRYPTOPROVIDER_BOUNCYCASTLE)
				&& Security.getProvider(SOSIFactory.PROPERTYVALUE_SOSI_CRYPTOPROVIDER_BOUNCYCASTLE) == null) {

			try {
				Provider provider = (Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider").newInstance();
				Security.addProvider(provider);
			} catch (InstantiationException e) {
				throw new ModelException("Provider could not be set", e);
			} catch (IllegalAccessException e) {
				throw new ModelException("Provider could not be set", e);
			} catch (ClassNotFoundException e) {
				throw new ModelException("Provider could not be set", e);
			}
		}
		return cryptoProvider;
	}

	/**
	 * Returns a Properties object containing a default setup of
	 * cryptoproviders based on the running vm
	 *
	 * Only IBM, SUN 1.4+ is supported by now
	 */
	public static Properties setupCryptoProviderForJVM() {
		Properties properties = new Properties();
		if("IBM Corporation".equals(System.getProperty("java.vm.vendor"))) {
			properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_PKCS12, "BC");
			properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_X509, "BC");
			properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_RSA, "IBMJCE");
			properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_SHA1WITHRSA, "IBMJCE");
		} else { // else SUN
			if ("1.4".equals(System.getProperty("java.specification.version"))) {
				properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_PKCS12, "BC");
			} else { // else 1.5+
				properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_PKCS12, "SunJSSE");
			}
			if ("1.6".equals(System.getProperty("java.specification.version"))) {
				properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_X509, "BC");
			} else if ("1.4".equals(System.getProperty("java.specification.version"))) {
                properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_X509, "BC");
            } else { // else 1.5
				properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_X509, "SUN");
			}
			properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_RSA, "SunRsaSign");
			properties.put(SOSIFactory.PROPERTYNAME_SOSI_CRYPTOPROVIDER_SHA1WITHRSA, "SunRsaSign");
		}
		return properties;
	}

	/**
	 * Returns the exclusive canonical XML for the specified DOM element (see @link{http://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/} for further details).
	 *
	 * @param domElement the element to canonicalize
	 */
	public static String getC14NString(Element domElement) 	throws XMLSecurityException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Canonicalizer c14nizer = Canonicalizer.getInstance("http://www.w3.org/2001/10/xml-exc-c14n#");
	    c14nizer.setWriter(new BufferedOutputStream(baos));
	     c14nizer.canonicalizeSubtree(domElement);
		return baos.toString();
	}

	// ====================================
	// Private stuff
	// ====================================
	/**
	 * Internal utility for initializing an XMLSignature structure with the supplied referenceURIs. The XMLSignature will use RSAwithSHA1 as signature
	 * algorithm and C14n_OMIT_COMMENTS as the digest algorithm.
	 *
	 * @param doc
     * @param config
     * @return An initialized XMLSignature
	 */
	 private static XMLSignature initXmlSignature(Document doc, SignatureConfiguration config) {
         String baseURI = doc.getDocumentElement().getNamespaceURI();

         XMLSignature xmlSignature;
         try {
             xmlSignature = new XMLSignature(doc, baseURI, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
         } catch (XMLSecurityException e) {
             throw new ModelException("Unable to get XMLSignature object", e);
         }

         SignatureConfiguration.Reference[] references = config.getReferences();
         for (int i = 0; i < references.length; i++) {
             processReference(doc, xmlSignature, references[i]);
         }

         Element xmlSigElement = xmlSignature.getElement();
         if (config.getIdAttributeName() != null) {
            xmlSigElement.setAttributeNS(null, config.getIdAttributeName(), IDValues.OCES_SIGNATURE);
         }

         Element signatureParentLocation = (Element) XmlUtil.getElementByIdExtended(doc, config.getSignatureParentID());

         // Create a DOMSignContext and specify the RSA PrivateKey and
         // location of the resulting XMLSignature's parent element
         if (signatureParentLocation == null) {
             signatureParentLocation = doc.getDocumentElement();
         }

         // Make sure to add the signature DOM element
         if (config.getSignatureSiblingNode() != null) {
             signatureParentLocation.insertBefore(xmlSigElement, config.getSignatureSiblingNode());
         } else {
             signatureParentLocation.appendChild(xmlSigElement);
         }

         return xmlSignature;
     }

    private static void processReference(Document doc, XMLSignature xmlSignature, SignatureConfiguration.Reference reference) {
        String referenceURI = reference.getURI();
        Transforms transforms = new Transforms(doc);
        try {
            switch (reference.getType()) {
                case DIRECT_REFERENCE_NOT_ENVELOPED:
                    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    break;
                case DIRECT_REFERENCE:
                    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
                    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    break;
                case SECURITY_TOKEN_REFERENCE:
                    transforms.addTransform(STRTransform.implementedTransformURI, createSTRParameters(doc));
                    break;
            }
        } catch (TransformationException e) {
            throw new ModelException("Unable to add c14n omit comments gctransform to reference " + referenceURI, e);
        }

        try {
            xmlSignature.addDocument("#" + referenceURI, transforms);
        } catch (XMLSignatureException e) {
            throw new ModelException("Unable to add transforms for reference " + referenceURI, e);
        }
    }

    private static Element createSTRParameters(Document doc) {
        Element parameters = doc.createElementNS(NameSpaces.WSSE_SCHEMA, WSSETags.TRANSFORMATION_PARAMETERS_PREFIXED);
        Element canonicalization = doc.createElementNS(NameSpaces.DSIG_SCHEMA, DSTags.CANONICALIZATION_METHOD_PREFIXED);
        //canonicalization.setAttribute(DSAttributes.ALGORITHM, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        canonicalization.setAttributeNS(null, DSAttributes.ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        parameters.appendChild(canonicalization);
        return parameters;
    }

    /**
	 * Remove superfluous xmlns:ds declarations on the signature generated by Apache. Removes "\n" Text nodes in the signature element.
	 *
	 * @param element
	 *            The XmlSignature element
	 */
	private static void tidyXML(Element element) {

		NamedNodeMap attributes = element.getAttributes();
		for (int i = 0; i < attributes.getLength(); i++) {
			Attr item = (Attr) attributes.item(i);
			if (item.getNodeName().startsWith("xmlns:"))
				element.removeAttributeNode(item);
		}

		NodeList children = element.getChildNodes();
		List<Text> lfElements = new LinkedList<Text>();
		for (int i = 0; i < children.getLength(); i++) {
			Node item = children.item(i);
			if (item.getNodeType() == Node.ELEMENT_NODE) {
				tidyXML((Element) item);
			} else if (item.getNodeType() == Node.TEXT_NODE) {
				// lfElements.add(item);
				Text textElement = ((Text) item);
				String value = ((Text) item).getData();
				if (value.indexOf('\n') >= 0) {
					if (value.length() == 1) {
						// Schedule this element for removal
						lfElements.add(textElement);
					} else {
						// Just remove the newline
						textElement.setData(value.replaceAll("\n", ""));
					}
				}
			}
		}

		// Remove all linefeed elements
		for (Iterator<Text> iter = lfElements.iterator(); iter.hasNext();) {
			element.removeChild(iter.next());
		}
	}

	private static boolean internalValidateIgnoreTrust(Node signatureToValidate, Federation federation) {
        return internalValidate(signatureToValidate, federation, null, false);
	}

	private static boolean internalValidate(Node signatureToValidate, Federation federation, CredentialVault vault, boolean checkForTrustedCertificates) {
        WSDocInfo wsDocInfo = new WSDocInfo(signatureToValidate.getOwnerDocument());
        WSDocInfoStore.store(wsDocInfo);
        try {

            String baseUri = signatureToValidate.getOwnerDocument().getDocumentElement().getNamespaceURI();

            if (baseUri == null) {
                baseUri = "";
            }

            if (signatureToValidate.getNodeType() != Node.ELEMENT_NODE) {
                throw new ModelException("The signature to validate must be a ds:Signature Element!");
            }

            XMLSignature xmlSignature;
            try {
                xmlSignature = new XMLSignature((Element) signatureToValidate, baseUri);
            } catch (XMLSecurityException e) {
                throw new ModelException("Unable to get XMLSignature element", e);
            }

            X509Certificate cert = resolveCertificate(xmlSignature, federation);

            // Check that the certificate used for validation is trusted. If a Federation has been specified
            // the signature must have been created by the STS. If no federation is specified, the
            // certificate must be trusted in the CredentialVault.
            if (checkForTrustedCertificates) {
                boolean trusted = false;
                if (federation != null) {
                    trusted = federation.isValidSTSCertificate(cert);
                } else if (vault != null) {
                    trusted = vault.isTrustedCertificate(cert);
                }
                if (!trusted) {
                    throw new ModelException("The certificate that signed the security token is not trusted!");
                }

            }

            // Make sure that the ID elements references from the Reference elements
            // can be looked up!
            XmlUtil.ensureEnvelopedIds((Element) signatureToValidate);

            try {
                return xmlSignature.checkSignatureValue(cert);
            } catch (XMLSignatureException e) {
                throw new ModelException("Unable to validate the xmlSignature", e);
            }
        } finally {
            WSDocInfoStore.delete(wsDocInfo);
        }
    }

    private static X509Certificate resolveCertificate(XMLSignature xmlSignature, Federation federation) {
        KeyInfo keyInfo = xmlSignature.getKeyInfo();
        if (keyInfo.containsKeyName()) {
            String keyName = resolveSingleKeyName(federation, keyInfo);
            FederationCertificateReference federationCertificateReference = new FederationCertificateReference(keyName);
            return federation.getFederationCertificate(federationCertificateReference);
        } else {
            try {
                return keyInfo.getX509Certificate();
            } catch (KeyResolverException e) {
                throw new ModelException("Unable to get certificate from dom", e);
            }
        }
    }

    private static String resolveSingleKeyName(Federation federation, KeyInfo keyInfo) {
        int keyNameCount = keyInfo.lengthKeyName();
        if (keyNameCount > 1) {
            throw new ModelException("Unable to handle more than one keyname");
        }
        if (keyNameCount > 0 && federation == null) {
            throw new ModelException("Will need federation to lookup certificate by keyName");
        }
        try {
            return keyInfo.itemKeyName(0).getKeyName();
        } catch (XMLSecurityException e) {
            throw new ModelException("Unable to lookup keyName", e);
        }
    }

}