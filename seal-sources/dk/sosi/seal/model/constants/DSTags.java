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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/constants/DSTags.java $
 * $Id: DSTags.java 10347 2012-10-18 14:29:15Z ChristianGasser $
 */
package dk.sosi.seal.model.constants;

/**
 * @author chg
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 10347 $
 * @since 1.0
 */
public enum DSTags implements Tag {
        x509Certificate("X509Certificate"),
        x509Data("X509Data"),
        keyInfo("KeyInfo"),
        keyName("KeyName"),
        signature("Signature");

	@Deprecated
    public static final String X509Certificate = "X509Certificate";
	public static final String X509CERTIFICATE = "X509Certificate";
	public static final String X509CERTIFICATE_PREFIXED = NameSpaces.NS_DS + ":" + X509CERTIFICATE;
	public static final String X509DATA_PREFIXED = NameSpaces.NS_DS + ":X509Data";
	public static final String KEY_INFO = "KeyInfo";
	public static final String KEY_INFO_PREFIXED = NameSpaces.NS_DS + ":" + KEY_INFO;
	public static final String KEY_NAME_PREFIXED = NameSpaces.NS_DS + ":KeyName";
	public static final String SIGNATURE = "Signature";
	public static final String SIGNATURE_PREFIXED = NameSpaces.NS_DS + ":Signature";
    public static final String SIGNATURE_VALUE = "SignatureValue";
	public static final String RETRIEVAL_METHOD_PREFIXED = NameSpaces.NS_DS + ":RetrievalMethod";
    public static final String CANONICALIZATION_METHOD_PREFIXED = NameSpaces.NS_DS + ":CanonicalizationMethod";
    public static final String REFERENCE = "Reference";

    private final String attribute;

    private DSTags(String attribute) {
        this.attribute = attribute;
    }
    
    public String getNS() {
        return NameSpaces.DSIG_SCHEMA;
    }
    public String getPrefix() {
        return NameSpaces.NS_DS;
    }

    public String getTagName() {
        return attribute;
    }
}
