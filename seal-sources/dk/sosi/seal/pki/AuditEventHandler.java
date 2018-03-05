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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/AuditEventHandler.java $
 * $Id: AuditEventHandler.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */

package dk.sosi.seal.pki;

/**
 * Interface to be implemented by users wishing to handle auditing events.
 * 
 * @author peter@signaturgruppen.dk
 * @author $LastChangedBy: chg@lakeside.dk $
 * @version $Revision: 8697 $
 * @since 1.0
 */
public interface AuditEventHandler {

	public static final String EVENT_TYPE_INFO_FEDERATION_INITIALIZED = "EVENT_TYPE_INFO_FEDERATION_INITIALIZED";
	public static final String EVENT_TYPE_INFO_CREDENTIAL_VAULT_INITIALIZED = "EVENT_TYPE_INFO_CREDENTIAL_VAULT_INITIALIZED";
	public static final String EVENT_TYPE_INFO_SOSI_XML_VALIDATED = "EVENT_TYPE_INFO_SOSI_XML_VALIDATED";
	public static final String EVENT_TYPE_INFO_CERTIFICATE_VALIDATED = "EVENT_TYPE_INFO_CERTIFICATE_VALIDATED";
	public static final String EVENT_TYPE_INFO_FULL_CRL_DOWNLOADED = "EVENT_TYPE_INFO_FULL_CRL_DOWNLOADED";
	
	/**
	 * callback Method in case of an informational auditing event
	 * 
	 * EVENT_TYPE_INFO_FEDERATION_INITIALIZED
	 * params[0] federation
	 * 
	 * EVENT_TYPE_INFO_CREDENTIAL_VAULT_INITIALIZED
	 * params[0] vault
	 * 
	 * EVENT_TYPE_INFO_SOSI_XML_VALIDATED
	 * params[0] XML document
	 * 
	 * EVENT_TYPE_INFO_CERTIFICATE_VALIDATED
	 * params[0] X509Certificate
	 * 
	 * EVENT_TYPE_INFO_FULL_CRL_DOWNLOADED
	 * params[0] CRLURL
	 * params[1] CRL
	 * 

	 * @param event
	 * 		description of event
	 * @param params
	 * 		Array of parameters 
	 */
	void onInformationalAuditingEvent(String event, Object[] params);
	
	String EVENT_TYPE_WARNING_NO_REVOCATION_CHECK = "EVENT_TYPE_WARNING_NO_REVOCATION_CHECK";
	/**
	 * callback Method in case of a warning auditing event
	 * 
	 * EVENT_TYPE_WARNING_NO_REVOCATION_CHECK
	 * params[0] X509Certificate
	 * 
	 * 
	 * @param event
	 * 		description of event
	 * @param params
	 * 		Array of parameters 
	 */
	void onWarningAuditingEvent(String event, Object[] params);
	
	String EVENT_TYPE_ERROR_DOWNLOADING_FULL_CRL = "EVENT_TYPE_ERROR_DOWNLOADING_FULL_CRL";
	String EVENT_TYPE_ERROR_FULL_CRL_EXPIRED = "EVENT_TYPE_ERROR_FULL_CRL_EXPIRED";
	String EVENT_TYPE_ERROR_PARSING_SOSI_XML = "EVENT_TYPE_ERROR_PARSING_SOSI_XML";
	String EVENT_TYPE_ERROR_VALIDATING_SOSI_MESSAGE = "EVENT_TYPE_ERROR_VALIDATING_SOSI_XML";
	String EVENT_TYPE_ERROR_VALIDATING_STS_CERTIFICATE = "EVENT_TYPE_ERROR_VALIDATING_STS_CERTIFICATE";
	String EVENT_TYPE_ERROR_VALIDATING_CERTIFICATE = "EVENT_TYPE_ERROR_VALIDATING_CERTIFICATE";
	/**
	 * callback Method in case of an error auditing event
	 * 
	 * EVENT_TYPE_ERROR_DOWNLOADING_FULL_CRL
	 * params[0] CRLURL
	 * 
	 * EVENT_TYPE_ERROR_FULL_CRL_EXPIRED
	 * params[0] CRLURL
	 * params[1] CRL
	 * params[2] Date 
	 * 
	 * EVENT_TYPE_ERROR_PARSING_SOSI_XML
	 * params[0] XML document
	 * 
	 * EVENT_TYPE_ERROR_VALIDATING_SOSI_MESSAGE
	 * params[0] SOSI Message
	 * 
	 * EVENT_TYPE_ERROR_VALIDATING_STS_CERTIFICATE
	 * params[0] X509Certificate
	 * 
	 * EVENT_TYPE_ERROR_VALIDATING_CERTIFICATE
	 * params[0] X509Certificate
	 *
	 * 
	 * @param event
	 * 		description of event
	 * @param params
	 * 		Array of parameters 
	 */
	void onErrorAuditingEvent(String event, Object[] params);
	
}
