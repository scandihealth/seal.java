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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/constants/FaultCodeValues.java $
 * $Id: FaultCodeValues.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */

/**
 * Valid statuscodes for &lt;medcom:FaultCode&gt;. Used in
 * soap:Fault/detail/medcom:FaultCode.
 * 
 * @author kkj
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
package dk.sosi.seal.model.constants;

public interface FaultCodeValues {

	String SYNTAX_ERROR = "syntax_error";
	String MISSING_REQUIRED_HEADER = "missing_required_header";
	String SECURITY_LEVEL_FAILED = "security_level_failed";
	String INVALID_USERNAME_PASSWORD = "invalid_username_password";
	String INVALID_SIGNATURE = "invalid_signature";
	String INVALID_IDCARD = "invalid_idcard";
	String INVALID_CERTIFICATE = "invalid_certificate";
	String EXPIRED_IDCARD = "expired_idcard";
	String NOT_AUTHORIZED = "not_authorized";
	String ILLEGAL_HTTP_METHOD = "illegal_http_method";
	String PROCESSING_PROBLEM = "processing_problem";

}
