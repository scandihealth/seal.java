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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/constants/MedComTags.java $
 * $Id: MedComTags.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.model.constants;

/**
 * XML tags for being consistent with the MedCom web service standard.
 * 
 * @author kkj
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public interface MedComTags {

	// Response specific tags
	String FLOW_STATUS = "FlowStatus";
	String IN_RESPONSE_TO_MESSAGE_ID = "InResponseToMessageID";
	String REQUIRE_NON_REPUDIATION_RECEIPT = "RequireNonRepudiationReceipt";
	
	String FLOW_STATUS_PREFIXED = NameSpaces.NS_MEDCOM + ":FlowStatus";
	String IN_RESPONSE_TO_MESSAGE_ID_PREFIXED = NameSpaces.NS_MEDCOM + ":InResponseToMessageID";
	String REQUIRE_NON_REPUDIATION_RECEIPT_PREFIXED = NameSpaces.NS_MEDCOM + ":RequireNonRepudiationReceipt";

	// Other tags
	String MESSAGE_ID = "MessageID";
	String FLOW_ID = "FlowID";
	String LINKING = "Linking";
	String SECURITY_LEVEL = "SecurityLevel";
	String HEADER = "Header";
	String FAULT_CODE = "FaultCode";

	String MESSAGE_ID_PREFIXED = NameSpaces.NS_MEDCOM + ":MessageID";
	String FLOW_ID_PREFIXED = NameSpaces.NS_MEDCOM + ":FlowID";
	String LINKING_PREFIXED = NameSpaces.NS_MEDCOM + ":Linking";
	String SECURITY_LEVEL_PREFIXED = NameSpaces.NS_MEDCOM + ":SecurityLevel";
	String HEADER_PREFIXED = NameSpaces.NS_MEDCOM + ":Header";
	String FAULT_CODE_PREFIXED = NameSpaces.NS_MEDCOM + ":FaultCode";
}
