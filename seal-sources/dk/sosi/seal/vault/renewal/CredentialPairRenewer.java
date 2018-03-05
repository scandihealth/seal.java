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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/vault/renewal/CredentialPairRenewer.java $
 * $Id: CredentialPairRenewer.java 20818 2014-12-18 11:26:29Z ChristianGasser $
 */

package dk.sosi.seal.vault.renewal;

import dk.sosi.seal.vault.CredentialPair;
import dk.sosi.seal.vault.renewal.model.RenewalException;

import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Interface to be implemented by credential pair renewers.
 * 
 * @author thomas@signaturgruppen.dk
 * @author $LastChangedBy: ChristianGasser $
 * @version $Revision: 20818 $
 * @since 1.0
 */
@Deprecated
public abstract class CredentialPairRenewer { //NOPMD

	protected Properties properties;
	
	/**
	 * Factory method for creating CredentialPairRenewers. 
	 * @param certificate	
	 * 			the certificate, for which a CredentialPairRenewer is needed
	 * @return
	 * 			suitable CredentialPairRenewer
	 * @throws RenewalException
	 * 			if no credential pair renewer capable of renewing the passed certificate can be found
	 */
	public static CredentialPairRenewer createInstance(X509Certificate certificate, Properties properties) throws RenewalException {
		return new TDCCredentialPairRenewer(properties);
	}

	/**
	 * Renew credential pair by contacting TDC renewal ws. The certificate must be issued by TDC OCES CA
	 * or by TDC OCES Systemtest CA II (test certificates only). 
	 * @param credentialPair
	 * 		the credential pair to be renewed
	 * @return
	 * 		renewed credential pair
	 */
	public abstract CredentialPair renew(CredentialPair credentialPair) throws RenewalException;
	
	/**
	 * Renewal of a certificate is likely to be a chargeable service from the Certificate Authority.
	 * By calling this method before the actual renewal takes place, clients are able to warn users
	 * that they are about to do something, that will cost money.
	 * 
	 * 
	 * @param certificate   
	 * 			candidate for renewal
	 * @return
	 * 			true, if renewal of the passed certificate costs money, false otherwise
	 */
	public abstract boolean isRenewalChargeable(X509Certificate certificate);

}
