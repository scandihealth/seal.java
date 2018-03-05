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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/pki/CommonsLoggingAuditEventHandler.java $
 * $Id: CommonsLoggingAuditEventHandler.java 20765 2014-12-10 12:59:03Z ChristianGasser $
 */

package dk.sosi.seal.pki;

import dk.sosi.seal.model.Message;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.XmlUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Default implementation of interface AuditEventHandler
 * Logging with apache commons.logging
 * 
 * @author peter@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20765 $
 * @since 1.0
 */
public class CommonsLoggingAuditEventHandler implements AuditEventHandler { //NOPMD
	
	private static final String AUDIT_LOGGER_NAME = "dk.sosi.seal.AUDIT";
	private static final Log log = LogFactory.getLog(AUDIT_LOGGER_NAME);

	
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
	public void onInformationalAuditingEvent(String event, Object[] params){
//	    System.out.println(log.getClass());
		 if (EVENT_TYPE_INFO_FEDERATION_INITIALIZED.equals(event)) {
			 Federation federation = (Federation) params[0];
			 log.info("Federation initialized: " + federation.getClass().getName());

		 } else if (EVENT_TYPE_INFO_CREDENTIAL_VAULT_INITIALIZED.equals(event)) {
			 CredentialVault credentialVault = (CredentialVault) params[0];
			 if (credentialVault.getSystemCredentialPair() != null) {
				 log.info("Credential vault initialized: " + credentialVault.getClass().getName() + ", key " + getSubjectDN(credentialVault.getSystemCredentialPair().getCertificate()));
			 } else {
				 log.info("Credential vault initialized: " + credentialVault.getClass().getName());
			 }

		 } else if (EVENT_TYPE_INFO_SOSI_XML_VALIDATED.equals(event)) {
			 Document XML  = (Document) params[0];
			 log.info("XML validated: " + XmlUtil.node2String(XML, false, true));

		 } else if (EVENT_TYPE_INFO_CERTIFICATE_VALIDATED.equals(event)) {
			 X509Certificate certificate  = (X509Certificate) params[0];
			 log.info("Certificate validated: " + getSubjectDN(certificate));

		 } else if (EVENT_TYPE_INFO_FULL_CRL_DOWNLOADED.equals(event)) {
			 String url  = (String) params[0];
			 log.info("CRL downloaded: " + url);
			 
		} else {
			log.info("Unkown event "  + event);
		}
	}
	
	/**
	 * callback Method in case of a warning auditing event
	 *
	 * EVENT_TYPE_WARNING_NO_REVOCATION_CHECK
	 * params[0] X509Certificate
	 * 
	 * @param event
	 * 		description of event
	 * @param params
	 * 		Array of parameters 
	 */
	public void onWarningAuditingEvent(String event, Object[] params){
		 if (EVENT_TYPE_WARNING_NO_REVOCATION_CHECK.equals(event)) {
			 X509Certificate certificate  = (X509Certificate) params[0];
			 log.warn("Certificate not checked for revocation: " + getSubjectDN(certificate));
		 } else {
			log.warn("Unkown event "  + event);
		}
	}
	
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
	public void onErrorAuditingEvent(String event, Object[] params){
		 if (EVENT_TYPE_ERROR_DOWNLOADING_FULL_CRL.equals(event)) {
			 String url  = (String) params[0];
			 log.error("Error downloading full CRL: " + url);
		} else if (EVENT_TYPE_ERROR_FULL_CRL_EXPIRED.equals(event)) {
			 String url  = (String) params[0];
			 //X509CRL crl  = (X509CRL) params[1];
			 Date expired  = (Date) params[2];
			 log.error("CRL expired: " + url + " expired at " + expired.toString());
		} else if (EVENT_TYPE_ERROR_PARSING_SOSI_XML.equals(event)) {
			 Document XML  = (Document) params[0];
			 log.error("Error parsing XML" + XmlUtil.node2String(XML, false, true));
		} else if (EVENT_TYPE_ERROR_VALIDATING_SOSI_MESSAGE.equals(event)) {
			 Message message = (Message) params[0];
			 log.error("Error validating SOSI Message" + XmlUtil.node2String(message.serialize2DOMDocument(), false, true));
		} else if (EVENT_TYPE_ERROR_VALIDATING_STS_CERTIFICATE.equals(event)) {
			 X509Certificate certificate  = (X509Certificate) params[0];
			 log.error("Error validating STS certificate: " + getSubjectDN(certificate));
		} else if (EVENT_TYPE_ERROR_VALIDATING_CERTIFICATE.equals(event)) {
			 X509Certificate certificate  = (X509Certificate) params[0];
			 log.error("Error validating certificate: " + getSubjectDN(certificate));
		} else {
			log.error("Unkown event "  + event);
		}
	}

    private String getSubjectDN(X509Certificate certificate) {
        return new DistinguishedName(certificate.getSubjectX500Principal()).toString();
    }

}