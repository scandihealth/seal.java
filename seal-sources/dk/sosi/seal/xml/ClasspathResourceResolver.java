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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/xml/ClasspathResourceResolver.java $
 * $Id: ClasspathResourceResolver.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.xml;

import dk.sosi.seal.model.ModelException;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;

import java.io.*;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Resourceresolver that will load schemas from the classpath.
 * @author ${user}
 * @author $$LastChangedBy: chg@lakeside.dk $$
 * @version $$Revision: 8697 $$
 * @since 1.3
 */
public class ClasspathResourceResolver implements EntityResolver {

	protected Map<String, String> inputMap;

	public ClasspathResourceResolver() throws ModelException {
		super();
		inputMap = Collections.synchronizedMap(new HashMap<String,String>());
	}

	/**
	 * Get the schema as string specified by systemId either from the
	 * cache or by loading it from the classpath. After loading, the schema will
	 * be cached for future lookups.
	 * @param systemId
	 *            The name of the schema to get e.g. soap.xsd
	 *
	 * @return Schema as String
	 * @throws IOException
	 */
	private String getInput(String systemId) throws IOException {
		String resourceAsString = inputMap.get(systemId);
		if (resourceAsString == null ) {
			String xsd = (systemId.lastIndexOf("/") != -1) ? systemId.substring(systemId.lastIndexOf("/")) : systemId;
			//TODO maybe it is nicer to use contextclassloader to get resources?
			//InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(xsd);
			InputStream inputStream = getClass().getResourceAsStream(xsd);
			if (inputStream != null)
				resourceAsString = consumeStream(inputStream);
			inputMap.put(systemId, resourceAsString);
		}
		return resourceAsString;
	}

	/**
	 * Callback. Resolve the resource (schema) specified by the input
	 * parameters.
	 *
	 * @param publicId
	 * @param systemId
	 * @return InputSource for the schema
	 * @throws IOException
	 */
	public InputSource resolveEntity(String publicId, String systemId) throws IOException {
		String resourceAsString = getInput(systemId);
		InputSource is = new InputSource(new StringReader(resourceAsString));
		is.setPublicId(publicId);
		is.setSystemId(systemId);
		return is;
	}

	public InputStream getResourceAsStream(String resource) throws IOException {
		String resourceAsString = getInput(resource);
		return new ByteArrayInputStream(resourceAsString.getBytes(XmlUtil.XML_ENCODING));
	}

	private String consumeStream(InputStream is) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer = new byte[8192];
		int n;
		while ((n = is.read(buffer, 0, buffer.length)) != -1) {
			baos.write(buffer, 0, n);
		}
		return baos.toString(XmlUtil.XML_ENCODING);
	}

}
