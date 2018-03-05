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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/ssl/HttpsConnectorImpl.java $
 * $Id: HttpsConnectorImpl.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.ssl;

import dk.sosi.seal.vault.CredentialPair;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.*;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * HTTPS helper class that hides the SSL connection details.
 *  
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public class HttpsConnectorImpl implements HttpsConnector {
	
	private SOSIKeyManager keyManager;
	private SOSITrustManager trustManager;

	/**
	 * Construct an instance of the helper class.  
	 * 
	 * @param clientCredentialPair 
	 * 			Client credentials to present to the server. Pass null, if no credentials should be used.
	 * @param trustedServerCertificateIssuers 
	 * 			Array of trusted server certificate issuers. Pass null, if no server certificate issuers should be trusted.
	 * 			Trusted issuers may be added later by calling @see dk.sosi.seal.vault.HttpsHelter#post .
	 */
	public HttpsConnectorImpl(CredentialPair clientCredentialPair, X509Certificate[] trustedServerCertificateIssuers) {
		this(trustedServerCertificateIssuers);
		if(clientCredentialPair != null) { 
			keyManager = new SOSIKeyManager(clientCredentialPair);
		}
	}

	/**
	 * Construct an instance of the helper class.  
	 * 
	 * @param trustedServerCertificateIssuers 
	 * 			Array of trusted server certificate issuers. Pass null, if no server certificate issuers should be trusted.
	 * 			Trusted issuers may be added later by calling @see dk.sosi.seal.vault.HttpsHelter#post .
	 */
	public HttpsConnectorImpl(X509Certificate[] trustedServerCertificateIssuers) {
		super();
		trustManager = new SOSITrustManager();
		if(trustedServerCertificateIssuers != null) {
			for (int i = 0; i < trustedServerCertificateIssuers.length; i++) {
				trustManager.addTrustedCertificate(trustedServerCertificateIssuers[i]);
			}
		}
	}

	
	public String postSOAP(String message, URL url) throws IOException {
		Map<String, String> props = new HashMap<String, String>();
		props.put("SOAPAction", "");
		props.put("Content-Type", "text/xml");
		return post(message, url, props);
	}
	
	public String post(String message, URL url, Map<String, String> requestProperties) throws IOException {
		SSLContext context = getSSLContext();
		
		HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
		
		connection.setSSLSocketFactory(context.getSocketFactory());
		connection.setDoOutput(true);
		connection.setDoInput(true);
		connection.setRequestMethod("POST");
		
		if(requestProperties != null) {
			Set<String> keys = requestProperties.keySet();
			for (Iterator<String> iter = keys.iterator(); iter.hasNext();) {
				String key = iter.next();
				connection.setRequestProperty(key, requestProperties.get(key));
			}
		}

		OutputStream out = connection.getOutputStream();
		Writer wout = new OutputStreamWriter(out);
		wout.write(message);
		wout.flush();

		// Get the response

		InputStream in = connection.getInputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		StringBuffer response = new StringBuffer();
		String line;
		while ((line = reader.readLine()) != null) { //NOPMD
			response.append(line);
		}
		return response.toString();
		
	}

	private SSLContext getSSLContext() throws IOException {
		SSLContext context;
		try {
			context = SSLContext.getInstance("TLS");
			if(keyManager != null) {
				context.init(new KeyManager[]{keyManager}, new TrustManager[]{trustManager}, null);
			} else {
				context.init(null, new TrustManager[]{trustManager}, null);
			}
			
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("Caught exception while setting up trust management: " + e);
		} catch (KeyManagementException e) {
			throw new IOException("Caught exception while setting up trust management: " + e);
		}
		return context;
	}
	
	public void addTrustedServerCertificateIssuer(X509Certificate trusted) {
		trustManager.addTrustedCertificate(trusted);
	}
	

}
