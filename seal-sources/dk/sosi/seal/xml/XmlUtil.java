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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/xml/XmlUtil.java $
 * $Id: XmlUtil.java 33209 2016-06-02 14:25:17Z ChristianGasser $
 */
package dk.sosi.seal.xml;

import dk.sosi.seal.SOSIFactory;
import dk.sosi.seal.model.ModelException;
import dk.sosi.seal.pki.AuditEventHandler;
import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.utils.IdResolver;
import org.apache.xml.utils.PrefixResolver;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.*;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * XML utility functions. <p/>
 *
 * @author kkj
 * @author $LastChangedBy: ChristianGasser $
 * @since 1.0
 */
public class XmlUtil {

	public static final String XML_ENCODING = "UTF-8";

	public static String SCHEMA_LANGUAGE = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
	public static String XML_SCHEMA = "http://www.w3.org/2001/XMLSchema";
	public static String SCHEMA_SOURCE = "http://java.sun.com/xml/jaxp/properties/schemaSource";

	private static final char[] HEXCHARS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	private static final int DEFAULT_INDENT = 2;

	/**
	 * Schema full checking feature id
	 * (http://apache.org/xml/features/validation/schema-full-checking).
	 */
	protected static final String SCHEMA_FULL_CHECKING_FEATURE_ID = "http://apache.org/xml/features/validation/schema-full-checking";

	/**
	 * Honour all schema locations feature id
	 * (http://apache.org/xml/features/honour-all-schemaLocations).
	 */
	protected static final String HONOUR_ALL_SCHEMA_LOCATIONS_ID = "http://apache.org/xml/features/honour-all-schemaLocations";

	/**
	 * Validate schema annotations feature id
	 * (http://apache.org/xml/features/validate-annotations)
	 */
	protected static final String VALIDATE_ANNOTATIONS_ID = "http://apache.org/xml/features/validate-annotations";

	/**
	 * Generate synthetic schema annotations feature id
	 * (http://apache.org/xml/features/generate-synthetic-annotations).
	 */
	protected static final String GENERATE_SYNTHETIC_ANNOTATIONS_ID = "http://apache.org/xml/features/generate-synthetic-annotations";

	static final DocumentBuilderFactory CACHED_DOCUMENT_BUILDER_FACTORY;

	private final static Document EMPTY_DOCUMENT;

	private static ClasspathResourceResolver resourceResolver = new ClasspathResourceResolver();

	static {
		// Initialize and cache a DocumentBuilderFactory and an empty document at class load
		CACHED_DOCUMENT_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();
		try {
			EMPTY_DOCUMENT = CACHED_DOCUMENT_BUILDER_FACTORY.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			throw new XmlUtilException("Unable to initialize cached empty document", e);
		}
	}

	// default settings

	/**
	 * Note: SimpleDateFormat is not thread safe, hence we can't have it as a
	 * static local.
	 * @param useZuluTime
	 * 		whether the formatter should convert dates to UTC and represent them as such
	 * @return Dateformatter, following DGWS dateTime format.
	 */
	public static DateFormat getDateFormat(boolean useZuluTime) {
		String formatString = "yyyy'-'MM'-'dd'T'HH:mm:ss";
		if (useZuluTime) {
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat(formatString + "'Z'");
			simpleDateFormat.setTimeZone(TimeZone.getTimeZone("Etc/UTC"));
			return simpleDateFormat;
		} else {
			return new SimpleDateFormat(formatString);
		}
	}

	/**
	 * Create a new document builder from the cached factory
	 *
     * @param validate if <code>true</code> the resulting <code>DocumentBuilder</code> will validate against XML Schema
     * @param useCachedFactory  if <code>true</code> the <code>DocumentBuilder</code> will be drawn from the cached <code>DocumentBuilderFactory</code>.
     *
     * @return A document builder
	 */
	protected static DocumentBuilder getDocumentBuilder(boolean validate, boolean useCachedFactory, String rootSchema) {

		DocumentBuilder documentBuilder;

		try {
			// DOMSource
			DocumentBuilderFactory docBuilderFactory;
			if(!useCachedFactory) {
				docBuilderFactory = DocumentBuilderFactory.newInstance();
			} else {
				docBuilderFactory = CACHED_DOCUMENT_BUILDER_FACTORY;
			}

            InputStream schemaStream = null;
            if (validate) {
                schemaStream = resourceResolver.getResourceAsStream("/" + rootSchema);
            }

            synchronized(docBuilderFactory) {
                // If the docBuilderFactory is a thread-common resource, the usage must be synchronized otherwise it is not thread-safe.
                // By synchronizing on the docBuilderFactory object this will only result in a lock, when using  the cached factory.
                if(validate) {
                    docBuilderFactory.setAttribute(SCHEMA_LANGUAGE, XML_SCHEMA);
                    docBuilderFactory.setAttribute(SCHEMA_SOURCE, schemaStream);
                }

                docBuilderFactory.setNamespaceAware(true);
                docBuilderFactory.setValidating(validate);

				documentBuilder = docBuilderFactory.newDocumentBuilder();
				documentBuilder.setEntityResolver(resourceResolver );
			}
		} catch (ParserConfigurationException e) {
			throw new XmlUtilException("Unable to initialize XML parser", e);
		} catch (IOException e) {
			throw new XmlUtilException("Unable to initialize XML parser", e);
		}

		documentBuilder.setErrorHandler(new DebugErrorHandler(false));
		return documentBuilder;
	}

    /**
     * crete a pretty string representation of this xml string
     */
    public static String getPrettyString(String xml) {
        Document doc = readXml(new Properties(), xml, false);
        return node2String(doc.getDocumentElement(), true, true);
    }

	/**
	 * Convert an XML representation of a String to a DOM Document
	 *
	 * @param xml  XML String
	 * @param properties  A Property Set containing information about auditlogging classes etc.
	 * @param validate If <code>true</code> the document will be XMLSchema validated while parsed
	 *
	 * @return Document representing the XML
	 */
	public static Document readXml(Properties properties, String xml, boolean validate) throws XmlUtilException {
		return readXml(properties, new InputSource(new StringReader(xml)), validate);
	}

	public static Element getElementByIdAndTagNameNS(String tag, String namespace, String id, Document document) {
	    
	    NodeList nodes;
	    if(namespace == null) {
	        nodes = document.getElementsByTagName(tag);
	    } else {
	        nodes = document.getElementsByTagNameNS(namespace, tag);
	    }
	    
		if (nodes.getLength() == 0) {
			return null; // NOPMD
		}

		for (int i = 0; i < nodes.getLength(); i++) {

			Node node = nodes.item(i);
			NamedNodeMap attributes = node.getAttributes();

			for (int j = 0; j < attributes.getLength(); j++) {

				Node attribute = attributes.item(j);
				String name = attribute.getNodeName().toLowerCase();

				if (name.equals("wsu:id") || (name.equals("id"))) {
					String attributeValue = attribute.getNodeValue();
					if (id.equalsIgnoreCase(attributeValue)) {
						return (Element) node; // NOPMD
					}
				}
			}

		}
		return null;
	}

	/**
	 * Read an xml input source and optionally validate it against the schema.
	 * Only schema validation will be performed (ie. no xml signature checking
	 * done here).
	 *
	 * @param isXml
	 *            The input source with the XML in it
	 * @param validate
	 *            True, if local schema validation is turned on
	 * @return The Document
	 * @throws XmlUtilException
	 *             If parsing failed, validation failed
	 */
	public static Document readXml(Properties properties, InputSource isXml, boolean validate) throws XmlUtilException {

		boolean useDocumentFactoryCache = properties.getProperty(SOSIFactory.PROPERTYNAME_SOSI_USE_DOCUMENT_BUILDER_FACTORY_CACHE, SOSIFactory.PROPERTYVALUE_SOSI_USE_DOCUMENT_BUILDER_FACTORY_CACHE).equalsIgnoreCase("true");
		boolean useEnhancedValidation = properties.getProperty(SOSIFactory.PROPERTYNAME_SOSI_VALIDATE_ENHANCED, SOSIFactory.PROPERTYVALUE_SOSI_VALIDATE_ENHANCED).equalsIgnoreCase("true");

        String defaultSchema = "soap.xsd";
        if(useEnhancedValidation) defaultSchema = "soap-specialized.xsd";

        String rootSchema = properties.getProperty(SOSIFactory.PROPERTYNAME_SOSI_ROOTSCHEMA, defaultSchema);

		DocumentBuilder documentBuilder = getDocumentBuilder(validate, useDocumentFactoryCache, rootSchema);

		Document doc = null;
		try {
			doc = documentBuilder.parse(isXml);
		} catch (SAXException e) {
			SOSIFactory.getAuditEventHandler(properties).onInformationalAuditingEvent(
					AuditEventHandler.EVENT_TYPE_ERROR_PARSING_SOSI_XML,
					new Object[]{doc}
					);
			throw new XmlUtilException("Unable to parse XML", e);
		} catch (IOException e) {
			SOSIFactory.getAuditEventHandler(properties).onInformationalAuditingEvent(
					AuditEventHandler.EVENT_TYPE_ERROR_PARSING_SOSI_XML,
					new Object[]{doc}
					);
			throw new XmlUtilException("Unable to parse XML", e);
		}

		SOSIFactory.getAuditEventHandler(properties).onInformationalAuditingEvent(
				AuditEventHandler.EVENT_TYPE_INFO_SOSI_XML_VALIDATED,
				new Object[]{doc}
				);

		return doc;

	}

	/**
	 * Convert the supplied set of bytes to base64 encoding
	 *
	 * @param bytes
	 *            Bytes to convert
	 * @return Base64 representation of bytes
	 */
	public static String toBase64(byte[] bytes) {
		return Base64.encodeBase64String(bytes);
	}

	/**
	 * Convert the supplied base 64 encoded string to raw bytes
	 *
	 * @param data
	 *            Base 64 encoded string
	 * @return raw byte representation
	 */
	public static byte[] fromBase64(String data) {
	    return Base64.decodeBase64(data);
	}

	/**
	 * Create empty document.
	 */
	public static Document createEmptyDocument() {
		synchronized(EMPTY_DOCUMENT) {
			return (Document) EMPTY_DOCUMENT.cloneNode(false);
		}
	}

	/**
	 * Convert the supplied byte array to a hex string
	 *
	 * @param bytes
	 *            to convert
	 * @return A hexadecimal string representation of the supplied bytes
	 */
	public static String toHex(byte[] bytes) {

		int i = 0;
		StringBuffer stringBuffer = new StringBuffer();
		while (i < bytes.length) {
			byte curByte = bytes[i++];
			stringBuffer.append(HEXCHARS[(curByte & 0xF0) >> 4]).append(HEXCHARS[curByte & 0x0F]);
		}
		return stringBuffer.toString();
	}

	/**
	 * given a <node>text</node>, return the value of text textnode embedded
	 * inside.
	 *
	 * @param parent
	 *            The node that has a textnode child element
	 * @return The node value of the text node
	 * @throws XmlUtilException
	 *             If the node is not a textnode.
	 */
	public static String getTextNodeValue(Node parent) throws XmlUtilException {

        NodeList children = parent.getChildNodes();
        if (children.getLength() == 0) {
            throw new XmlUtilException("The supplied element " + node2String(parent, false, false) + " doesn't have child nodes");
        }

        Node child = children.item(0);

        if (child.getNodeType() != Node.TEXT_NODE && child.getNodeType() != Node.CDATA_SECTION_NODE) {
            throw new XmlUtilException("The first child of the supplied node (" + node2String(parent, false, false) + ") is not a text element");
        }

        return child.getNodeValue();
    }

    public static Element getFirstChildElementNS(Element parent, String namespaceURI, String localName) {
        final NodeList childNodes = parent.getChildNodes();

        for (int i = 0; i < childNodes.getLength(); i++) {
            final Node childNode = childNodes.item(i);
            if (childNode instanceof Element) {
                Element childElement = (Element) childNode;
                if (localName.equals(childElement.getLocalName()) && namespaceURI.equals(childElement.getNamespaceURI())) {
                    return childElement;
                }
            }
        }

        return null;
    }

    public static List<Element> getChildElementsNS(Element parent, String namespaceURI, String localName) {
        final NodeList childNodes = parent.getChildNodes();

        List<Element> elements = new LinkedList<Element>();

        for (int i = 0; i < childNodes.getLength(); i++) {
            final Node childNode = childNodes.item(i);
            if (childNode instanceof Element) {
                Element childElement = (Element) childNode;
                if (localName.equals(childElement.getLocalName()) && namespaceURI.equals(childElement.getNamespaceURI())) {
                    elements.add(childElement);
                }
            }
        }

        return elements;
    }

    /**
	 * Serialize the supplied DOM node to string including an <code><?xml ...></code> header and without prettyprinting.
	 *
	 * Calls node2String(node, false, true);
	 *
	 * @param node
	 *            The node to serialize
	 * @return DOM as XML String
	 */
	public static String node2String(Node node) {
		return node2String(node, false, true);
	}

	/**
	 * Serialize the supplied DOM node to string form. This result is configurable through parameterettings.
	 * <p/>
	 * <b>WARNING: </b>If the DOM document contains digital signatures (more precisely <code><SignedInfo></code> elements the signatures
	 * will be broken if the XML document is formatted through pretty-printing!
	 *
	 * @param node
	 *            The node to serialize
	 * @param pretty
	 *            If true, will indent and generally pretty-print XML. Note:
	 *            This may affect validity of  contained digital signatures!
	 * @param includeXMLHeader
	 *            If true, add the standard XML header to the output
	 * @return DOM as XML String
	 */
	public static String node2String(Node node, boolean pretty, boolean includeXMLHeader) {

		ByteArrayOutputStream bas = new ByteArrayOutputStream();
		try {
			TransformerFactory factory = TransformerFactory.newInstance();
			Transformer transformer = factory.newTransformer();

			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			transformer.setOutputProperty(OutputKeys.INDENT, (pretty) ? "yes" : "no");
			transformer.setOutputProperty(OutputKeys.ENCODING, XML_ENCODING);
			transformer.setOutputProperty("{http://xml.apache.org/xalan}indent-amount", Integer.toString(DEFAULT_INDENT));

			transformer.transform(new DOMSource(node), new StreamResult(bas));

			String str = bas.toString(XML_ENCODING);
			if(includeXMLHeader) {
				str = "<?xml version=\"1.0\" encoding=\""+XML_ENCODING+"\" ?>"+((pretty)?"\n"+str:str);
			}
			return str;
		} catch (TransformerConfigurationException e) {
			throw new XmlUtilException("TransformerConfigurationException during prettyPrint", e);
		} catch (TransformerException e) {
			throw new XmlUtilException("TransformerException during prettyPrint", e);
		} catch (UnsupportedEncodingException e) {
			throw new XmlUtilException("Unsupported XML encoding", e);
		}
	}

	public static byte[] serializeXml2ByteArray(Node node, boolean includeXMLHeader) {

		// output the resulting document
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		TransformerFactory tf = TransformerFactory.newInstance();
		try {
			Transformer trans = tf.newTransformer();
			trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, (includeXMLHeader) ? "no" : "yes");
			trans.setOutputProperty(OutputKeys.METHOD, "xml");
			trans.transform(new DOMSource(node), new StreamResult(os));
		} catch (TransformerException e) {
			throw new XmlUtilException("Unable to gctransform input", e);
		}
		return os.toByteArray();
	}

	/**
	 * Find the first child of the parent element of the specified nodeType.
	 * Note: This method does a recursive scan of all elements in the subtree
	 * until at match is found. Use with caution.
	 *
	 * @param parent
	 * @param nodeType
	 * @return The first child element of the specified nodeType
	 */
	public static Node findChildElement(Node parent, String nodeType) {

		NodeList children = parent.getChildNodes();
		if (children.getLength() == 0)
			return null; // NOPMD

		for (int i = 0; i < children.getLength(); i++) {

			Node child = children.item(i);
			if (child.getNodeName().equals(nodeType))
				return child; // NOPMD
			child = findChildElement(child, nodeType);
			if (child != null)
				return child; // NOPMD
		}

		return null;
	}

	/**
	 * Convert a byte array to an X509 certificate
     *
     * Use the method in CertificateParser instead
	 *
	 * @param value
	 *            The byte array to convert
	 * @return The X509 certificate
	 * @throws ModelException
	 *             if conversion fails
	 */
    @Deprecated
	public static X509Certificate getByteArrayAsCertificate(byte[] value) {
        return CertificateParser.asCertificate(value);
	}

	/**
	 * See http://www.w3.org/TR/2001/REC-xmlschema-2-20010502/#dateTime
	 * @param useZuluTime
	 * 			whether to convert the date to UTC and represent it accordingly
	 */
	public static String toXMLTimeStamp(Date date, boolean useZuluTime) {

		return getDateFormat(useZuluTime).format(date);
	}

	/**
	 * See http://www.w3.org/TR/2001/REC-xmlschema-2-20010502/#dateTime
	 */
	public static Date fromXMLTimeStamp(String xmlTimestamp) throws ParseException {

		if (xmlTimestamp == null)
			throw new ModelException("xmlTimestamp cannot be null");
		boolean useZuluTime = isZuluTimeFormat(xmlTimestamp);
		return getDateFormat(useZuluTime).parse(xmlTimestamp);
	}

	public static boolean isZuluTimeFormat(String xmlTimestamp) {
		return xmlTimestamp != null && xmlTimestamp.endsWith("Z");
	}

    public static Date parseZuluDateTime(String dateTimeString) {
        if (dateTimeString == null || dateTimeString.trim().length() == 0) {
            throw new IllegalArgumentException("DateTimeString cannot be null or empty");
        }
        String formatString = "yyyy'-'MM'-'dd'T'HH:mm:ss";

        List<DateFormat> dateFormats = new LinkedList<DateFormat>();

        SimpleDateFormat format = new SimpleDateFormat(formatString + "'Z'");
        format.setTimeZone(TimeZone.getTimeZone("Etc/UTC"));
        dateFormats.add(format);

        SimpleDateFormat formatWithMillis = new SimpleDateFormat(formatString + ".SSS'Z'");
        formatWithMillis.setTimeZone(TimeZone.getTimeZone("Etc/UTC"));
        dateFormats.add(formatWithMillis);

        for (DateFormat dateFormat : dateFormats) {
            try {
                return  dateFormat.parse(dateTimeString);
            } catch (ParseException e) {
                //Ignore
            }
        }

        throw  new ModelException(String.format("DateTimeString is not formatted as Zulu-time: %s", dateTimeString));

    }

	// this moves the timeconsuming instantiation of SecureRandom
	// from first messagegeneration to class init
	static {
		createGUID();
	}

	//TODO use UUID algorithm based on standards (JDK1.5, Commons Id contains such a generator)
	public static String createGUID() {
	    return toBase64(createUIDBytes(16));
	}

    public static String generateUUID() {
        return "urn:uuid:" + UUID.randomUUID();
    }

    public static String generateRandomNCName() {
        return "_" + UUID.randomUUID();
    }

	public static String createNonce() {

		long now = System.currentTimeMillis();
		byte[] nonce = new byte[20];

		// Copy currentTimeMillis to the upper 8 bytes
		for (int i = 0; i < 8; i++) {
			nonce[7 - i] = (byte) (now & 0xFF);
			now = now >>> 8;
		}

		// Copy 8 random bytes to the lower 8 bytes
		System.arraycopy(createUIDBytes(8), 0, nonce, 8, 8);

		// Place a "magic" in the upper 4 bytes
		nonce[16] = 0x53;
		nonce[17] = 0x4F;
		nonce[18] = 0x53;
		nonce[19] = 0x49;

		return toBase64(nonce);
	}

	/**
	 * Create a SHA-1 hash of the supplied bytes
	 *
	 * @param bytes
	 *            The bytes to create a hash for
	 * @return The SHA-1 message digest of the supplied bytes
	 */
	public static byte[] getSha1Digest(byte[] bytes) {

		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			throw new ModelException("Unable to get SHA-1 algorithm for message digest", e);
		}
		return messageDigest.digest(bytes);
	}

	/**
	 * Deep and thorough search for any attribute that lowercased ends with "id"
	 * and whose name value matches the reference uri. Potentially very
	 * expensive operation.
	 *
	 * @param root
	 *            The start of the search
	 * @param referenceUri
	 *            The id value to look for
	 * @return Null if not found, the Attribute node otherwise.
	 */
	public static Node getElementByIdExtended(Node root, String referenceUri) {

		NamedNodeMap namedNodeMap = root.getAttributes();
		if (namedNodeMap != null) {
			for (int i = 0; i < namedNodeMap.getLength(); i++) {

				Node node = namedNodeMap.item(i);
				String name = node.getNodeName().toLowerCase();
				if (name.endsWith("id")) {
					String value = node.getNodeValue();
					//if (referenceUri.equals(value))
                    if (value.equals(referenceUri))
						return root; // NOPMD
				}
			}
		}

		NodeList children = root.getChildNodes();
		for (int i = 0; i < children.getLength(); i++) {
			Node candidate = getElementByIdExtended(children.item(i), referenceUri);
			if (candidate != null)
				return candidate; // NOPMD
		}

		return null;
	}

	/**
	 * Traverse the node hierarchy upwards to the root, adding each attribute
	 * that ends with "id" (case ignored) as an Id to the IdResolver for future
	 * lookups. This is necessary when validating external documents that use
	 * extended ids such as wsu:id, which are not discovered by normal DOM
	 * lookup means.
	 *
	 * @param startElement
	 *            The element at which to start the addition
	 */
	public static void ensureEnvelopedIds(Element startElement) {

		registerElementByIdExtended(startElement);

		Node childParent = startElement.getParentNode();
		while (childParent != null) {
			if (childParent.getNodeType() == Node.ELEMENT_NODE) {
				registerElementByIdExtended((Element) childParent);
			}
			childParent = childParent.getParentNode();
		}
	}

	/**
	 * Run thru the attributes of the element, adding any attribute that ends
	 * with "id" (case ignored) as an Id to the IdResolver.
	 *
	 * @param element
	 *            The element for which to add ids.
	 */
	public static void registerElementByIdExtended(Element element) {

		NamedNodeMap namedNodeMap = element.getAttributes();
		if (namedNodeMap != null) {
			for (int i = 0; i < namedNodeMap.getLength(); i++) {

				Node node = namedNodeMap.item(i);
				String name = node.getNodeName().toLowerCase();
				if (name.endsWith("id")) {
					String value = node.getNodeValue();
					IdResolver.registerElementById(element, value);
				}
			}
		}

	}

	/**
	 * Makes a deep compare of two DOM nodes and returns the first subnode that
	 * differs in the two DOM representations. The comparisson is significant in
	 * respect to order of attributes and children.
	 *
	 * @param node1
	 *            The first node to compare
	 * @param node2
	 *            The second node to compare
	 * @return <code>null</code> if the two Nodes are equal, or the first
	 *         subnode that differs.
	 */
	public static Node deepDiff(Node node1, Node node2) {

		Node result;
		if (!node1.getNodeName().equals(node2.getNodeName())
				|| ((node1.getNamespaceURI() == null || node2.getNamespaceURI() == null) && node1.getNamespaceURI() != node2.getNamespaceURI())) {
			return node1; // NOPMD
		}

		// Compare attributes
		NamedNodeMap node1List = node1.getAttributes();
		NamedNodeMap node2List = node2.getAttributes();
		if (node1List != null && node2List != null) {
			if (node1List.getLength() != node2List.getLength())
				return node1; // NOPMD
			for (int i = 0; i < node1List.getLength(); i++) { // size is compared above
				if ((result = deepDiff(node1List.item(i), node2List.item(i))) != null) // NOPMD
					return result; // NOPMD
			}
		} else if (node1List != node2List) {
			return node1; // NOPMD
		}

		// Compare children
		NodeList children1 = node1.getChildNodes();
		NodeList children2 = node2.getChildNodes();
		if (children1 != null && children2 != null) {
			if (children1.getLength() != children2.getLength())
				return node1; // NOPMD
			for (int i = 0; i < children1.getLength(); i++) { // size is compared above
				if ((result = deepDiff(children1.item(i), children2.item(i))) != null) // NOPMD
					return result; // NOPMD
			}
		} else if (children1 != children2) {
			return node1; // NOPMD
		}
		return null;
	}

	/**
	 * Selects a single Element based on an xpath expression
	 *
	 * @param node
	 * 			The starting Node from which the xpath expression is evaluated
	 * @param xpath
	 * 			The xpath expression
	 * @param resolver
	 * 			The PefixResolver used
	 * @param failIfNoneOrMultipleAreFound
     *          Whether to fail if none or multiple element match the expression
     * @return
	 * 			The element if the expression matches exactly one element or <code>null</null> otherwise.
	 */
	public static Element selectSingleElement(Node node, String xpath, PrefixResolver resolver, boolean failIfNoneOrMultipleAreFound) {
		try {
            NodeList nodeList = XPathAPI.eval(node, xpath, resolver).nodelist();
            int numberOfSelectedElements = nodeList.getLength();
            if (numberOfSelectedElements == 1) {
                return (Element) nodeList.item(0);
            } else if (failIfNoneOrMultipleAreFound){
                throw new XmlUtilException("Expected 1 XML element matching path '" + xpath + "' starting from '" + node.getPrefix() + ":" + node.getLocalName() + "' (prefixes are resolved and may be different in actual XML). Found " + numberOfSelectedElements + ".");
            } else {
                return null;
            }
		} catch (TransformerException e) {
			throw new XmlUtilException("Unable to get " + xpath, e);
		}
	}

	public static String removeFormatting(String xml) {
		return xml.replaceAll(">\\s*<", "><");
	}

	// ===================================
	// Private parts
	// ===================================

	private static byte[] createUIDBytes(int size) {

		SecureRandom secureRandom = new SecureRandom();
		byte[] probablyUniqueID = new byte[size];
		secureRandom.nextBytes(probablyUniqueID);
		return probablyUniqueID;
	}

}
