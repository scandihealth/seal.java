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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/constants/WSSETags.java $
 * $Id: WSSETags.java 9027 2011-10-03 15:02:36Z chg@lakeside.dk $
 */
package dk.sosi.seal.model.constants;

/**
 * Class containing WSSE XML tags.
 *
 * @author chg
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.5.11
 */
public enum WSSETags implements Tag {
    security("Security"),
    securityTokenReference("SecurityTokenReference");

    public static String USERNAME_TOKEN = "UsernameToken";
    public static String USERNAME = "Username";
    public static String PASSWORD = "Password";
    public static String SECURITY = "Security";
    public static String SECURITY_TOKEN_REFERENCE = "SecurityTokenReference";
    public static String KEY_IDENTIFIER = "KeyIdentifier";

    public static String USERNAME_TOKEN_PREFIXED = NameSpaces.NS_WSSE + ":" + USERNAME_TOKEN;
    public static String USERNAME_PREFIXED = NameSpaces.NS_WSSE + ":" + USERNAME;
    public static String PASSWORD_PREFIXED = NameSpaces.NS_WSSE + ":" + PASSWORD;
    public static String SECURITY_PREFIXED = NameSpaces.NS_WSSE + ":" + SECURITY;
    public static String SECURITY_TOKEN_REFERENCE_PREFIXED = NameSpaces.NS_WSSE + ":" + SECURITY_TOKEN_REFERENCE;
    public static String KEY_IDENTIFIER_PREFIXED = NameSpaces.NS_WSSE + ":" + KEY_IDENTIFIER;
    public static String REFERENCE_PREFIXED = NameSpaces.NS_WSSE + ":Reference";
    public static String TRANSFORMATION_PARAMETERS_PREFIXED = NameSpaces.NS_WSSE + ":TransformationParameters";

    private final String tagname;

    WSSETags(String tagname) {
        this.tagname = tagname;
    }

    public String getNS() {
        return NameSpaces.WSSE_SCHEMA;
    }

    public String getTagName() {
        return tagname;
    }

    public String getPrefix() {
        return NameSpaces.NS_WSSE;
    }
}
