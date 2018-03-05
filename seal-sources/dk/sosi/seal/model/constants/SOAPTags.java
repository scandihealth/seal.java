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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/constants/SOAPTags.java $
 * $Id: SOAPTags.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.model.constants;

/**
 * Class containing SOAP XML tags.
 * 
 * @author kkj
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public enum SOAPTags implements Tag {
        body("Body"),
        header("Header"),
        fault("Fault"), 
        envelope("Envelope"),
    ;
    
    public static final String BODY_UNPREFIXED = "Body";
    public static final String HEADER_UNPREFIXED = "Header";
    public static final String ENVELOPE_UNPREFIXED = "Envelope";

    @Deprecated
    public static final String BODY = NameSpaces.NS_SOAP + ":" + BODY_UNPREFIXED;
    public static final String BODY_PREFIXED = NameSpaces.NS_SOAP + ":" + BODY_UNPREFIXED;
    public static final String DETAIL = "detail";
    @Deprecated
    public static final String ENVELOPE = NameSpaces.NS_SOAP + ":Envelope";
    public static final String ENVELOPE_PREFIXED = NameSpaces.NS_SOAP + ":Envelope";
    @Deprecated
    public static final String FAULT = NameSpaces.NS_SOAP + ":Fault";
    public static final String FAULT_PREFIXED = NameSpaces.NS_SOAP + ":Fault";
    public static final String FAULTACTOR = "faultactor";
    public static final String FAULTCODE = "faultcode";
    public static final String FAULTSTRING = "faultstring";
    @Deprecated
    public static final String HEADER = NameSpaces.NS_SOAP + ":" + HEADER_UNPREFIXED;
    public static final String HEADER_PREFIXED = NameSpaces.NS_SOAP + ":" + HEADER_UNPREFIXED;
    private final String tag;
    
    private SOAPTags(String tag) {
        this.tag = tag;
    }
    
    public String getNS() {
        return NameSpaces.SOAP_SCHEMA;
    }
    public String getTagName() {
        return tag;
    }

    public String getPrefix() {
        return NameSpaces.NS_SOAP;
    }
}