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
 * $HeadURL: https://svn.softwareborsen.dk/sosi/trunk/modules/seal/src/main/java/dk/sosi/seal/model/constants/SubjectIdentifierTypeValues.java $
 * $Id: SubjectIdentifierTypeValues.java 8697 2011-09-02 10:33:55Z chg@lakeside.dk $
 */
package dk.sosi.seal.model.constants;

/**
 * Class containing XML type values.
 * 
 * @author kkj
 * @author $LastChangedBy: chg@lakeside.dk $
 * @since 1.0
 */
public interface SubjectIdentifierTypeValues {

	String CPR_NUMBER = NameSpaces.NS_MEDCOM + ":cprnumber";
	String Y_NUMBER = NameSpaces.NS_MEDCOM + ":ynumber";
	String P_NUMBER = NameSpaces.NS_MEDCOM + ":pnumber";
	String SKS_CODE = NameSpaces.NS_MEDCOM + ":skscode";
	String CVR_NUMBER = NameSpaces.NS_MEDCOM + ":cvrnumber";
	String COMMUNAL_NUMBER = NameSpaces.NS_MEDCOM + ":communalnumber";
	String LOCATION_NUMBER = NameSpaces.NS_MEDCOM + ":locationnumber";
	String IT_SYSTEM_NAME = NameSpaces.NS_MEDCOM + ":itsystemname";
	String OTHER = NameSpaces.NS_MEDCOM + ":other";

}
