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
 * $HeadURL$
 * $Id$
 */

package dk.sosi.seal.util;

import dk.sosi.seal.pki.testobjects.CredentialVaultAdapter;
import dk.sosi.seal.vault.CredentialVault;
import dk.sosi.seal.xml.CertificateParser;
import dk.sosi.seal.xml.XmlUtil;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/**
 * @author $LastChangedBy:$ $LastChangedDate:$
 * @version $Revision:$
 */
public class SOSITestUtils {

    // SSR: CVR:34051178-UID:1336055110451
    private final static String OLD_NEMLOGIN_IDP_CERTIFICATE_STRING =
            "MIIFrTCCBRagAwIBAgIEQDgeoDANBgkqhkiG9w0BAQUFADA/MQswCQYDVQQGEwJESzEMMAoGA1UE" +
            "ChMDVERDMSIwIAYDVQQDExlUREMgT0NFUyBTeXN0ZW10ZXN0IENBIElJMB4XDTEyMDUwNzEzMDIz" +
            "N1oXDTE0MDUwNzEzMzIzN1owgaIxCzAJBgNVBAYTAkRLMTEwLwYDVQQKEyhEaWdpdGFsaXNlcmlu" +
            "Z3NzdHlyZWxzZW4gLy8gQ1ZSOjM0MDUxMTc4MWAwJQYDVQQFEx5DVlI6MzQwNTExNzgtVUlEOjEz" +
            "MzYwNTUxMTA0NTEwNwYDVQQDEzBEaWdpdGFsaXNlcmluZ3NzdHlyZWxzZW4gLSBEaWdzdCAtIE5l" +
            "bUxvZy1pbiBUZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDnV90kgwkzKmuCtfAb" +
            "2OORg6DufFoLekR1jDfRyf8qYIkAGEELYiNuatR8o29/gEWibNy/W9i0cMNH44e9t6cPf6GXqqQl" +
            "FxbV6SWuX4LPMsq7kJiWw+kkV3Ac66jsKVEJduSxHRKfNiFq3Fg4AAFn7TsvQSAapHZXUwMpTNXf" +
            "qq6BkO9RvJjkMlj3TpDGIgiRMWyQmH84RsL/SjgiLDbkesCToWr8GylQVCascIfihwxxDNM3QJmz" +
            "t7oZuYX1+uZkQayq57vZxqGldvnhTuAjCNt7nN76Doy584D7kzPU2vrad0sNUrcvPzzHQBj2aKgw" +
            "uhColBOtLOjcELtKn0C7AgMBAAGjggLMMIICyDAOBgNVHQ8BAf8EBAMCA7gwKwYDVR0QBCQwIoAP" +
            "MjAxMjA1MDcxMzAyMzdagQ8yMDE0MDUwNzEzMzIzN1owRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUF" +
            "BzABhipodHRwOi8vdGVzdC5vY3NwLmNlcnRpZmlrYXQuZGsvb2NzcC9zdGF0dXMwggEDBgNVHSAE" +
            "gfswgfgwgfUGCSkBAQEBAQEBAzCB5zAvBggrBgEFBQcCARYjaHR0cDovL3d3dy5jZXJ0aWZpa2F0" +
            "LmRrL3JlcG9zaXRvcnkwgbMGCCsGAQUFBwICMIGmMAoWA1REQzADAgEBGoGXVERDIFRlc3QgQ2Vy" +
            "dGlmaWthdGVyIGZyYSBkZW5uZSBDQSB1ZHN0ZWRlcyB1bmRlciBPSUQgMS4xLjEuMS4xLjEuMS4x" +
            "LjEuMy4gVERDIFRlc3QgQ2VydGlmaWNhdGVzIGZyb20gdGhpcyBDQSBhcmUgaXNzdWVkIHVuZGVy" +
            "IE9JRCAxLjEuMS4xLjEuMS4xLjEuMS4zLjAcBglghkgBhvhCAQ0EDxYNb3JnYW5XZWJOb0RpcjAc" +
            "BgNVHREEFTATgRFuZW1sb2dpbkBkaWdzdC5kazCBlwYDVR0fBIGPMIGMMFegVaBTpFEwTzELMAkG" +
            "A1UEBhMCREsxDDAKBgNVBAoTA1REQzEiMCAGA1UEAxMZVERDIE9DRVMgU3lzdGVtdGVzdCBDQSBJ" +
            "STEOMAwGA1UEAxMFQ1JMMzIwMaAvoC2GK2h0dHA6Ly90ZXN0LmNybC5vY2VzLmNlcnRpZmlrYXQu" +
            "ZGsvb2Nlcy5jcmwwHwYDVR0jBBgwFoAUHJgJRxpMOLkQxQQpW/H0ToBqzH4wHQYDVR0OBBYEFKhW" +
            "lVALv2E2JYC8SQPu2jvRXVjqMAkGA1UdEwQCMAAwGQYJKoZIhvZ9B0EABAwwChsEVjcuMQMCA6gw" +
            "DQYJKoZIhvcNAQEFBQADgYEAQlw2hwwrFX9rehfxsMDkiOJGLJcVmSpK9bA/qDUCr8EU4aBfBE+o" +
            "IHaAQxmrG9Rsvyhf1rUE+Cir2GQsS5gcG9zIhwEwtCitQutM7dOJ1eIbApmHF8bHike8eouerTcr" +
            "oqM6EY8TbfEkDEtDuQxk+GqbCh5gpKg243ZLZiG3Aes=";

    //SERIALNUMBER=CVR:34051178-UID:83384970 + CN=Digitaliseringsstyrelsen - NemLog-in Test, O=Digitaliseringsstyrelsen // CVR:34051178, C=DK
    private final static String NEW_NEMLOGIN_IDP_CERTIFICATE_STRING =
            "MIIGRTCCBS2gAwIBAgIEUw8DszANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQGEwJESzESMBAGA1UE" +
            "CgwJVFJVU1QyNDA4MSQwIgYDVQQDDBtUUlVTVDI0MDggU3lzdGVtdGVzdCBYSVggQ0EwHhcNMTQw" +
            "NTA1MTMzNTU4WhcNMTcwNTA1MTMzNTEyWjCBljELMAkGA1UEBhMCREsxMTAvBgNVBAoMKERpZ2l0" +
            "YWxpc2VyaW5nc3N0eXJlbHNlbiAvLyBDVlI6MzQwNTExNzgxVDAgBgNVBAUTGUNWUjozNDA1MTE3" +
            "OC1VSUQ6ODMzODQ5NzAwMAYDVQQDDClEaWdpdGFsaXNlcmluZ3NzdHlyZWxzZW4gLSBOZW1Mb2ct" +
            "aW4gVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALnCmDRMztjDckSupQBLcEzr" +
            "RRJnAFxzEFdB7Cj6ApMQ/YxqKzfL/TSIr3v2mdgQNnsJGz91YbAteDPRHR/K1W3kqoIX/qH2uXDz" +
            "HK+qi4YD9D8s4MnHAt02x6t0TgKQGjn1XO6lgLQ563DjtgD2fdPm9USV2Lkxe5ofNRG7yvWowBWj" +
            "XKia8D64k6zSzoHKdPz6GCy9S0NmwIyJE0sJavcfwxT3/ia0g63/xD77SteT4H/OR/DLis7FLnfk" +
            "Lp8yrd5xAk4nEGizmjrg2OVJmIMMPK6PQdw+/lqSdgaPDxMD6yoIwWshux5Rup1+piMLg852odHR" +
            "6EhUzjEsi9DnWWcCAwEAAaOCAucwggLjMA4GA1UdDwEB/wQEAwIEsDCBlwYIKwYBBQUHAQEEgYow" +
            "gYcwPAYIKwYBBQUHMAGGMGh0dHA6Ly9vY3NwLnN5c3RlbXRlc3QxOS50cnVzdDI0MDguY29tL3Jl" +
            "c3BvbmRlcjBHBggrBgEFBQcwAoY7aHR0cDovL3YuYWlhLnN5c3RlbXRlc3QxOS50cnVzdDI0MDgu" +
            "Y29tL3N5c3RlbXRlc3QxOS1jYS5jZXIwggEgBgNVHSAEggEXMIIBEzCCAQ8GDSsGAQQBgfRRAgQG" +
            "AwQwgf0wLwYIKwYBBQUHAgEWI2h0dHA6Ly93d3cudHJ1c3QyNDA4LmNvbS9yZXBvc2l0b3J5MIHJ" +
            "BggrBgEFBQcCAjCBvDAMFgVEYW5JRDADAgEBGoGrRGFuSUQgdGVzdCBjZXJ0aWZpa2F0ZXIgZnJh" +
            "IGRlbm5lIENBIHVkc3RlZGVzIHVuZGVyIE9JRCAxLjMuNi4xLjQuMS4zMTMxMy4yLjQuNi4zLjQu" +
            "IERhbklEIHRlc3QgY2VydGlmaWNhdGVzIGZyb20gdGhpcyBDQSBhcmUgaXNzdWVkIHVuZGVyIE9J" +
            "RCAxLjMuNi4xLjQuMS4zMTMxMy4yLjQuNi4zLjQuMBwGA1UdEQQVMBOBEW5lbWxvZ2luQGRpZ3N0" +
            "LmRrMIGpBgNVHR8EgaEwgZ4wPKA6oDiGNmh0dHA6Ly9jcmwuc3lzdGVtdGVzdDE5LnRydXN0MjQw" +
            "OC5jb20vc3lzdGVtdGVzdDE5LmNybDBeoFygWqRYMFYxCzAJBgNVBAYTAkRLMRIwEAYDVQQKDAlU" +
            "UlVTVDI0MDgxJDAiBgNVBAMMG1RSVVNUMjQwOCBTeXN0ZW10ZXN0IFhJWCBDQTENMAsGA1UEAwwE" +
            "Q1JMMjAfBgNVHSMEGDAWgBTMAlUM5IF0ryBU1REUV5yRUjh/oDAdBgNVHQ4EFgQUwm9c3oUHE/zZ" +
            "/43g4RUhswnMVAowCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOCAQEACLh3Ovvljv4b/Ywf/8Wx" +
            "oB2y50Oqt8rpwXZp+no4d5tLqIMTSAlQxL0lAf4Qm4e6tF5m/55+dLwxw5/Dqwa0bQXHt98vJjSB" +
            "YLQH6rwfDzNmVGimO1n84k4MMYY449ykjqRNDfCS3+5+zV/An4CH9eUhvB0AHHWbD6eALw39sPGx" +
            "c5kHADTOdJ5SboSm9DHYdLLt9k8HyxrHIkcJApLWPgyFmkE0+8jtuQQluN62F5+j5d53oTKinHEd" +
            "7adM0ea537vNf5uBGu6h9OTXlhZwM9tlnrsTYQTTAIzdxGPlpD9Zvo5nmJHwILdRonm8rZf3vAm5" +
            "9/U6+Cht4+X2l5zxyg==";

    private final static String NEWEST_NEMLOGIN_IDP_CERTIFICATE_STRING = 
            "MIIGKTCCBRGgAwIBAgIEWBkD8TANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQGEwJE" +
            "SzESMBAGA1UECgwJVFJVU1QyNDA4MSQwIgYDVQQDDBtUUlVTVDI0MDggU3lzdGVt" +
            "dGVzdCBYSVggQ0EwHhcNMTcwNDIwMDgxODU2WhcNMjAwNDIwMDgxODI2WjCBljEL" +
            "MAkGA1UEBhMCREsxMTAvBgNVBAoMKERpZ2l0YWxpc2VyaW5nc3N0eXJlbHNlbiAv" +
            "LyBDVlI6MzQwNTExNzgxVDAgBgNVBAUTGUNWUjozNDA1MTE3OC1GSUQ6NTY5NDA0" +
            "MTMwMAYDVQQDDClOZW1Mb2ctaW4gQURGUyBUZXN0IChmdW5rdGlvbnNjZXJ0aWZp" +
            "a2F0KTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJu6nF+J1+5LfnOc" +
            "F1IetAM6RD9WA+5SPbfmMZFctyg4yifZL2ppkW7XUB5AUdZsFHpqFbZkTKbCeZFJ" +
            "IpiraeBDQZtHt7mdHtL8/UF262FCGZdIqP77Kct323rhYcQqd9HfU5iHJZJ1D+H2" +
            "zNdhqxnEGsTHivvg5Q2qtTUNh+nZqoAeBxPKEg3pHkhrs4QXqPPK+yBEcO8skhqd" +
            "pMuHBWzo0ciUKz/S8oqO7y8wySqR2p6tZCVIMJg6gqwNeUzbxOPRy1MDk2KXNXdI" +
            "6xGXtYQ/nUNnxSUl99/Dx0NxEXxMynZ6dJIL0RtqTfawtmGeR25LC3iE0WoLaeNB" +
            "gTnmyj8CAwEAAaOCAsswggLHMA4GA1UdDwEB/wQEAwIDuDCBlwYIKwYBBQUHAQEE" +
            "gYowgYcwPAYIKwYBBQUHMAGGMGh0dHA6Ly9vY3NwLnN5c3RlbXRlc3QxOS50cnVz" +
            "dDI0MDguY29tL3Jlc3BvbmRlcjBHBggrBgEFBQcwAoY7aHR0cDovL2YuYWlhLnN5" +
            "c3RlbXRlc3QxOS50cnVzdDI0MDguY29tL3N5c3RlbXRlc3QxOS1jYS5jZXIwggEg" +
            "BgNVHSAEggEXMIIBEzCCAQ8GDSsGAQQBgfRRAgQGBAIwgf0wLwYIKwYBBQUHAgEW" +
            "I2h0dHA6Ly93d3cudHJ1c3QyNDA4LmNvbS9yZXBvc2l0b3J5MIHJBggrBgEFBQcC" +
            "AjCBvDAMFgVEYW5JRDADAgEBGoGrRGFuSUQgdGVzdCBjZXJ0aWZpa2F0ZXIgZnJh" +
            "IGRlbm5lIENBIHVkc3RlZGVzIHVuZGVyIE9JRCAxLjMuNi4xLjQuMS4zMTMxMy4y" +
            "LjQuNi40LjIuIERhbklEIHRlc3QgY2VydGlmaWNhdGVzIGZyb20gdGhpcyBDQSBh" +
            "cmUgaXNzdWVkIHVuZGVyIE9JRCAxLjMuNi4xLjQuMS4zMTMxMy4yLjQuNi40LjIu" +
            "MIGrBgNVHR8EgaMwgaAwPKA6oDiGNmh0dHA6Ly9jcmwuc3lzdGVtdGVzdDE5LnRy" +
            "dXN0MjQwOC5jb20vc3lzdGVtdGVzdDE5LmNybDBgoF6gXKRaMFgxCzAJBgNVBAYT" +
            "AkRLMRIwEAYDVQQKDAlUUlVTVDI0MDgxJDAiBgNVBAMMG1RSVVNUMjQwOCBTeXN0" +
            "ZW10ZXN0IFhJWCBDQTEPMA0GA1UEAwwGQ1JMMTA2MB8GA1UdIwQYMBaAFMwCVQzk" +
            "gXSvIFTVERRXnJFSOH+gMB0GA1UdDgQWBBRn40IAgUyGNBLIe9WVpg4dp2w6rzAJ" +
            "BgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQANLBO8hF+ZyxkHZryhp6hLIPi9" +
            "tH2TWZNYvv/Y9NW/tWWmVYkgNNAecwpYsm5EzMAmlJiYF0KxZZ0jMIcyUM1q6aG8" +
            "TOnym8nDKw7kXNegLjH7ZO/uhPabRtCaJmyrYUnwRjgHVmB2h8rsfqV3ACdCAROG" +
            "8OSSgFdMs9hTHLQLOBxnbhXD+Ohv8taArKnXvgSEb4jbYa78SJ+WD/8Ov3CIlm/i" +
            "ABbTwPOu1oqa+2c3mURzgEZZlUAb8sor+0Ig1QW3zicDcIVVVk+EmV9SUMxOR437" +
            "wTJ2KYvU6XziTupCgMWLmrY52lIJ+uS4XMNmxoc60ajUyUZXFYEhVQkH85Qv";

    public final static X509Certificate OLD_NEMLOGIN_IDP_CERTIFICATE = CertificateParser.asCertificate(XmlUtil.fromBase64(OLD_NEMLOGIN_IDP_CERTIFICATE_STRING));

    public final static X509Certificate NEW_NEMLOGIN_IDP_CERTIFICATE = CertificateParser.asCertificate(XmlUtil.fromBase64(NEW_NEMLOGIN_IDP_CERTIFICATE_STRING));

    public final static X509Certificate NEWEST_NEMLOGIN_IDP_CERTIFICATE = CertificateParser.asCertificate(XmlUtil.fromBase64(NEWEST_NEMLOGIN_IDP_CERTIFICATE_STRING));

    public static String readXMLStreamAndRemoveFormatting(InputStream is) {
        String xml = new Scanner(is, "UTF-8").useDelimiter("\\A").next();
        return XmlUtil.removeFormatting(xml);
    }

    public static CredentialVault getOldIdPTrustVault() {
        return new CredentialVaultAdapter() {
            public boolean isTrustedCertificate(X509Certificate certificate) {
                return OLD_NEMLOGIN_IDP_CERTIFICATE.equals(certificate);
            }
        };
    }

    public static CredentialVault getNewIdPTrustVault() {
        return new CredentialVaultAdapter() {
            public boolean isTrustedCertificate(X509Certificate certificate) {
                return NEW_NEMLOGIN_IDP_CERTIFICATE.equals(certificate);
            }
        };
    }

    public static CredentialVault getNewestIdPTrustVault() {
        return new CredentialVaultAdapter() {
            public boolean isTrustedCertificate(X509Certificate certificate) {
                return NEWEST_NEMLOGIN_IDP_CERTIFICATE.equals(certificate);
            }
        };
    }

}
