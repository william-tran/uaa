/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import static org.junit.Assert.assertNotNull;

import org.junit.Assert;
import org.junit.Test;
import org.opensaml.xml.security.credential.Credential;

import java.util.Arrays;

public class SamlLoginServerKeyManagerTests {

    private SamlLoginServerKeyManager keyManager = null;

    @Test
    public void testWithWorkingCertificate() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "Proc-Type: 4,ENCRYPTED\n" +
                        "DEK-Info: DES-EDE3-CBC,5771044F3450A262\n" +
                        "\n" +
                        "VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe\n" +
                        "aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v\n" +
                        "CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh\n" +
                        "DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B\n" +
                        "+KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3\n" +
                        "KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU\n" +
                        "o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6\n" +
                        "NEl6E3CivddMHIPQWil5x4AMaevGa3v/gcZI0DN8t7L1g4fgjtSPYzvwmOxoxHGi\n" +
                        "7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI\n" +
                        "0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu\n" +
                        "h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9\n" +
                        "zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb\n" +
                        "dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==\n" +
                        "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                        "MIIB1TCCAT4CCQCpQCfJYT8ZJTANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDFCRz\n" +
                        "YW1sX2xvZ2luLE9VPXRlbXBlc3QsTz12bXdhcmUsTz1jb20wHhcNMTMwNzAyMDAw\n" +
                        "MzM3WhcNMTQwNzAyMDAwMzM3WjAvMS0wKwYDVQQDFCRzYW1sX2xvZ2luLE9VPXRl\n" +
                        "bXBlc3QsTz12bXdhcmUsTz1jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n" +
                        "ANK8mv+mUzhPH/8iTdMsZ6mY4r4At/GZIFS34L+/I0V2g6PkZ84VBgodqqV6Z6NY\n" +
                        "OSk0lcjrzU650zbES7yn4MjuvP0N5T9LydlvjOEzfA+uRETiy8d+DsS3rThRY+Ja\n" +
                        "dvmS0PswJ8cvHAksYmGNUWfTU+Roxcv0ZDqD+cUNi1+NAgMBAAEwDQYJKoZIhvcN\n" +
                        "AQEFBQADgYEAy54UVlZifk1PPdTg9OJuumdxgzZk3QEWZGjdJYEc134MeKKsIX50\n" +
                        "+6y5GDyXmxvJx33ySTZuRaaXClOuAtXRWpz0KlceujYuwboyUxhn46SUASD872nb\n" +
                        "cN0E1UrhDloFcftXEXudDL2S2cSQjsyxLNbBop63xq+U6MYG/uFe7GQ=\n" +
                        "-----END CERTIFICATE-----";
        String password = "password";

        keyManager = new SamlLoginServerKeyManager(key, password, certificate);
        Credential credential = keyManager.getDefaultCredential();
        assertNotNull(credential.getPrivateKey());
        assertNotNull(credential.getPublicKey());
        assertNotNull(credential);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWithWorkingCertificateInvalidPassword() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "Proc-Type: 4,ENCRYPTED\n" +
                        "DEK-Info: DES-EDE3-CBC,5771044F3450A262\n" +
                        "\n" +
                        "VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe\n" +
                        "aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v\n" +
                        "CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh\n" +
                        "DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B\n" +
                        "+KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3\n" +
                        "KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU\n" +
                        "o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6\n" +
                        "NEl6E3CivddMHIPQWil5x4AMaevGa3v/gcZI0DN8t7L1g4fgjtSPYzvwmOxoxHGi\n" +
                        "7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI\n" +
                        "0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu\n" +
                        "h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9\n" +
                        "zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb\n" +
                        "dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==\n" +
                        "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                        "MIIB1TCCAT4CCQCpQCfJYT8ZJTANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDFCRz\n" +
                        "YW1sX2xvZ2luLE9VPXRlbXBlc3QsTz12bXdhcmUsTz1jb20wHhcNMTMwNzAyMDAw\n" +
                        "MzM3WhcNMTQwNzAyMDAwMzM3WjAvMS0wKwYDVQQDFCRzYW1sX2xvZ2luLE9VPXRl\n" +
                        "bXBlc3QsTz12bXdhcmUsTz1jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n" +
                        "ANK8mv+mUzhPH/8iTdMsZ6mY4r4At/GZIFS34L+/I0V2g6PkZ84VBgodqqV6Z6NY\n" +
                        "OSk0lcjrzU650zbES7yn4MjuvP0N5T9LydlvjOEzfA+uRETiy8d+DsS3rThRY+Ja\n" +
                        "dvmS0PswJ8cvHAksYmGNUWfTU+Roxcv0ZDqD+cUNi1+NAgMBAAEwDQYJKoZIhvcN\n" +
                        "AQEFBQADgYEAy54UVlZifk1PPdTg9OJuumdxgzZk3QEWZGjdJYEc134MeKKsIX50\n" +
                        "+6y5GDyXmxvJx33ySTZuRaaXClOuAtXRWpz0KlceujYuwboyUxhn46SUASD872nb\n" +
                        "cN0E1UrhDloFcftXEXudDL2S2cSQjsyxLNbBop63xq+U6MYG/uFe7GQ=\n" +
                        "-----END CERTIFICATE-----";
        String password = "vmware";

        try {
            keyManager = new SamlLoginServerKeyManager(key, password, certificate);
            Assert.fail("Password invalid. Should not reach this line.");
        } catch (Exception x) {
            if (x.getClass().getName().equals("org.bouncycastle.openssl.EncryptionException")) {
                throw new IllegalArgumentException(x);
            } else if (x.getClass().equals(IllegalArgumentException.class)) {
                throw x;
            }
        }
    }

    @Test
    public void testWithWorkingCertificateNullPassword() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXgIBAAKBgQDfTLadf6QgJeS2XXImEHMsa+1O7MmIt44xaL77N2K+J/JGpfV3\n" +
            "AnkyB06wFZ02sBLB7hko42LIsVEOyTuUBird/3vlyHFKytG7UEt60Fl88SbAEfsU\n" +
            "JN1i1aSUlunPS/NCz+BKwwKFP9Ss3rNImE9Uc2LMvGy153LHFVW2zrjhTwIDAQAB\n" +
            "AoGBAJDh21LRcJITRBQ3CUs9PR1DYZPl+tUkE7RnPBMPWpf6ny3LnDp9dllJeHqz\n" +
            "a3ACSgleDSEEeCGzOt6XHnrqjYCKa42Z+Opnjx/OOpjyX1NAaswRtnb039jwv4gb\n" +
            "RlwT49Y17UAQpISOo7JFadCBoMG0ix8xr4ScY+zCSoG5v0BhAkEA8llNsiWBJF5r\n" +
            "LWQ6uimfdU2y1IPlkcGAvjekYDkdkHiRie725Dn4qRiXyABeaqNm2bpnD620Okwr\n" +
            "sf7LY+BMdwJBAOvgt/ZGwJrMOe/cHhbujtjBK/1CumJ4n2r5V1zPBFfLNXiKnpJ6\n" +
            "J/sRwmjgg4u3Anu1ENF3YsxYabflBnvOP+kCQCQ8VBCp6OhOMcpErT8+j/gTGQUL\n" +
            "f5zOiPhoC2zTvWbnkCNGlqXDQTnPUop1+6gILI2rgFNozoTU9MeVaEXTuLsCQQDC\n" +
            "AGuNpReYucwVGYet+LuITyjs/krp3qfPhhByhtndk4cBA5H0i4ACodKyC6Zl7Tmf\n" +
            "oYaZoYWi6DzbQQUaIsKxAkEA2rXQjQFsfnSm+w/9067ChWg46p4lq5Na2NpcpFgH\n" +
            "waZKhM1W0oB8MX78M+0fG3xGUtywTx0D4N7pr1Tk2GTgNw==\n" +
            "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEJTCCA46gAwIBAgIJANIqfxWTfhpkMA0GCSqGSIb3DQEBBQUAMIG+MQswCQYD\n" +
            "VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5j\n" +
            "aXNjbzEdMBsGA1UEChMUUGl2b3RhbCBTb2Z0d2FyZSBJbmMxJDAiBgNVBAsTG0Ns\n" +
            "b3VkIEZvdW5kcnkgSWRlbnRpdHkgVGVhbTEcMBoGA1UEAxMTaWRlbnRpdHkuY2Yt\n" +
            "YXBwLmNvbTEfMB0GCSqGSIb3DQEJARYQbWFyaXNzYUB0ZXN0Lm9yZzAeFw0xNTA1\n" +
            "MTQxNzE5MTBaFw0yNTA1MTExNzE5MTBaMIG+MQswCQYDVQQGEwJVUzETMBEGA1UE\n" +
            "CBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEdMBsGA1UEChMU\n" +
            "UGl2b3RhbCBTb2Z0d2FyZSBJbmMxJDAiBgNVBAsTG0Nsb3VkIEZvdW5kcnkgSWRl\n" +
            "bnRpdHkgVGVhbTEcMBoGA1UEAxMTaWRlbnRpdHkuY2YtYXBwLmNvbTEfMB0GCSqG\n" +
            "SIb3DQEJARYQbWFyaXNzYUB0ZXN0Lm9yZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw\n" +
            "gYkCgYEA30y2nX+kICXktl1yJhBzLGvtTuzJiLeOMWi++zdivifyRqX1dwJ5MgdO\n" +
            "sBWdNrASwe4ZKONiyLFRDsk7lAYq3f975chxSsrRu1BLetBZfPEmwBH7FCTdYtWk\n" +
            "lJbpz0vzQs/gSsMChT/UrN6zSJhPVHNizLxstedyxxVVts644U8CAwEAAaOCAScw\n" +
            "ggEjMB0GA1UdDgQWBBSvWY/TyHysYGxKvII95wD/CzE1AzCB8wYDVR0jBIHrMIHo\n" +
            "gBSvWY/TyHysYGxKvII95wD/CzE1A6GBxKSBwTCBvjELMAkGA1UEBhMCVVMxEzAR\n" +
            "BgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xHTAbBgNV\n" +
            "BAoTFFBpdm90YWwgU29mdHdhcmUgSW5jMSQwIgYDVQQLExtDbG91ZCBGb3VuZHJ5\n" +
            "IElkZW50aXR5IFRlYW0xHDAaBgNVBAMTE2lkZW50aXR5LmNmLWFwcC5jb20xHzAd\n" +
            "BgkqhkiG9w0BCQEWEG1hcmlzc2FAdGVzdC5vcmeCCQDSKn8Vk34aZDAMBgNVHRME\n" +
            "BTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBAL5j1JCN5EoXMOOBSBUL8KeVZFQD3Nfy\n" +
            "YkYKBatFEKdBFlAKLBdG+5KzE7sTYesn7EzBISHXFz3DhdK2tg+IF1DeSFVmFl2n\n" +
            "iVxQ1sYjo4kCugHBsWo+MpFH9VBLFzsMlP3eIDuVKe8aPXFKYCGhctZEJdQTKlja\n" +
            "lshe50nayKrT\n" +
            "-----END CERTIFICATE-----";
        String password = null;

        keyManager = new SamlLoginServerKeyManager(key, password, certificate);
        Credential credential = keyManager.getDefaultCredential();
        assertNotNull(credential.getPrivateKey());
        assertNotNull(credential.getPublicKey());
        assertNotNull(credential);
        System.out.println("certificate = " + certificate);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWithWorkingCertificateIllegalKey() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "Proc-Type: 4,ENCRYPTED\n" +
                        "DEK-Info: DES-EDE3-CBC,5771044F3450A262\n" +
                        "\n" +
                        "VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe\n" +
                        "aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v\n" +
                        "CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh\n" +
                        "DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B\n" +
                        "+KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3\n" +
                        "KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU\n" +
                        "o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6\n" +
                        "7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI\n" +
                        "0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu\n" +
                        "h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9\n" +
                        "zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb\n" +
                        "dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==\n" +
                        "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                        "MIIB1TCCAT4CCQCpQCfJYT8ZJTANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDFCRz\n" +
                        "YW1sX2xvZ2luLE9VPXRlbXBlc3QsTz12bXdhcmUsTz1jb20wHhcNMTMwNzAyMDAw\n" +
                        "MzM3WhcNMTQwNzAyMDAwMzM3WjAvMS0wKwYDVQQDFCRzYW1sX2xvZ2luLE9VPXRl\n" +
                        "bXBlc3QsTz12bXdhcmUsTz1jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n" +
                        "ANK8mv+mUzhPH/8iTdMsZ6mY4r4At/GZIFS34L+/I0V2g6PkZ84VBgodqqV6Z6NY\n" +
                        "OSk0lcjrzU650zbES7yn4MjuvP0N5T9LydlvjOEzfA+uRETiy8d+DsS3rThRY+Ja\n" +
                        "dvmS0PswJ8cvHAksYmGNUWfTU+Roxcv0ZDqD+cUNi1+NAgMBAAEwDQYJKoZIhvcN\n" +
                        "AQEFBQADgYEAy54UVlZifk1PPdTg9OJuumdxgzZk3QEWZGjdJYEc134MeKKsIX50\n" +
                        "+6y5GDyXmxvJx33ySTZuRaaXClOuAtXRWpz0KlceujYuwboyUxhn46SUASD872nb\n" +
                        "cN0E1UrhDloFcftXEXudDL2S2cSQjsyxLNbBop63xq+U6MYG/uFe7GQ=\n" +
                        "-----END CERTIFICATE-----";
        String password = "password";

        keyManager = new SamlLoginServerKeyManager(key, password, certificate);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testWithNonWorkingCertificate() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "Proc-Type: 4,ENCRYPTED\n" +
                        "DEK-Info: DES-EDE3-CBC,5771044F3450A262\n" +
                        "\n" +
                        "VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe\n" +
                        "aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v\n" +
                        "CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh\n" +
                        "DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B\n" +
                        "+KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3\n" +
                        "KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU\n" +
                        "o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6\n" +
                        "NEl6E3CivddMHIPQWil5x4AMaevGa3v/gcZI0DN8t7L1g4fgjtSPYzvwmOxoxHGi\n" +
                        "7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI\n" +
                        "0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu\n" +
                        "h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9\n" +
                        "zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb\n" +
                        "dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==\n" +
                        "-----END RSA PRIVATE KEY-----";
        String certificate = "-----BEGIN CERTIFICATE-----\n" +
                        "MIIB1TCCAT4CCQCpQCfJYT8ZJTANBgkqhkiG9w0BAQUFADAvMS0wKwYDVQQDFCRz\n" +
                        "YW1sX2xvZ2luLE9VPXRlbXBlc3QsTz12bXdhcmUsTz1jb20wHhcNMTMwNzAyMDAw\n" +
                        "MzM3WhcNMTQwNzAyMDAwMzM3WjAvMS0wKwYDVQQDFCRzYW1sX2xvZ2luLE9VPXRl\n" +
                        "bXBlc3QsTz12bXdhcmUsTz1jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n" +
                        "OSk0lcjrzU650zbES7yn4MjuvP0N5T9LydlvjOEzfA+uRETiy8d+DsS3rThRY+Ja\n" +
                        "dvmS0PswJ8cvHAksYmGNUWfTU+Roxcv0ZDqD+cUNi1+NAgMBAAEwDQYJKoZIhvcN\n" +
                        "AQEFBQADgYEAy54UVlZifk1PPdTg9OJuumdxgzZk3QEWZGjdJYEc134MeKKsIX50\n" +
                        "+6y5GDyXmxvJx33ySTZuRaaXClOuAtXRWpz0KlceujYuwboyUxhn46SUASD872nb\n" +
                        "cN0E1UrhDloFcftXEXudDL2S2cSQjsyxLNbBop63xq+U6MYG/uFe7GQ=\n" +
                        "-----END CERTIFICATE-----";
        String password = "password";

        try {
            keyManager = new SamlLoginServerKeyManager(key, password, certificate);
            Assert.fail("Key/Cert pair is invalid. Should not reach this line.");
        } catch (Exception x) {
            if (x.getClass().getName().equals("org.bouncycastle.openssl.PEMException")) {
                throw new IllegalArgumentException(x);
            } else if (x.getClass().getName().equals("org.bouncycastle.openssl.EncryptionException")) {
                throw new IllegalArgumentException(x);
            } else if (x.getClass().equals(IllegalArgumentException.class)) {
                throw x;
            }
        }
    }

    @Test
    public void testSreeKeys() throws Exception {
        String key = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "   MIIEpAIBAAKCAQEA8uaHlcy2DLLx2HwIzLhw7QIReHJ9sjKQpNV0aVsOjlKle7ig\n" +
            "   JMNZVtzj11UkCvVcjNfUEKgbM/c0MDpoMt50oOD99YUYNwQPhl4ZyOcB344Rp1Fq\n" +
            "   M2t2zzGeYm/Yox8SJ2bYcA6F6NBc6PzOR9Y2dmHICRnefLP+NwZ5hJ2Pqjc7MlNn\n" +
            "   7Sx3uNGQ7EcPHKbFrq4AwUFkXbNnIp6cOJDfhID81feff0HC/oYB1WaEBOlvmdZO\n" +
            "   MYQNhtPpMF1jW08bvBhNtawef64WlGAgYGdEE6MvYbU2zs4IfzqrtAbSdjPZ6ZC8\n" +
            "   SIfMwM7Z8jiCWuV60DOmMRfoK88PFnxo5MGfJQIDAQABAoIBAA818HepAh15dzuf\n" +
            "   SM3JHwk4f++S+9wU3onz8/5E/XxcIJDG1wB2WzndS0dIxaEKDGmlelowrMNsT5BV\n" +
            "   mADXfWY1sLGXTBTl5DL94Y97J9rgAqr/pi7iI+aFrO1tI5vTbkeZYSRjRG933Nma\n" +
            "   OzC0cWSoauZnAE++1cSMWz+6vixiec2YrB//iEeolcca7rxKaSuBgBqv3Q96DFDa\n" +
            "   2bCoD0ioEwFn10dgwr7Q79JC4XpG6KxhG7WnRgibfoPvJiC3tNVNpo5fz2c+q/Hy\n" +
            "   iOcDnasDglc7DOfFRRo81kHCvh3bhoyx+qzI7sW37y/7j5r6BPA0/YWfG8edK0vO\n" +
            "   rn7kfWECgYEA/ogbOqDOf1Ab8Nxs+Y5cGpL/OKSk9RxEGcYie1ol4Y7vMclRDr/J\n" +
            "   Sx/K3dWiCqo9EGzHfqKPg7+y7jtc3ZDVYtt+j+aFOhK2wzKwa99IgLn/x3XfRf2d\n" +
            "   NuWEeqgrnXO+Jm9tCC90zXhqOjcRjcrXGEH3IXJJ97ON4XjBPsi86EcCgYEA9E0/\n" +
            "   DlEhEminz/zYOQj6+5THgfys6w4XPLZch/LE0gAWzfOFlkky+KUdCNosCb/zjGHX\n" +
            "   6ZXBaFm/Od6xDIk8/m2rdzIPk6R6XtIP1tcrchgxS05OcmNE+Y2dNaABJAFb+dNu\n" +
            "   mLqIi5fRmr75EhiwExJbmYqd8gvoK48i0W8rXzMCgYEAsd+d37fW9wOdsxHnmfKR\n" +
            "   jQSjFQuCN8ScFsLu//L8vAcuQ0WjvsHqQvShyarsxbU4XU0XkPi7gF+sBG45tKDt\n" +
            "   bltjs95txiqjy/+VaJ0uRr8070gBUyEsB9wXW7xAVpU3EhcWQ/0eDCUVXz9ypftV\n" +
            "   m58lvBrpdA/nm+TObzjLQysCgYEA7OBNaJtfftL9C9005jB/8xoyTCZsn8lc3KBR\n" +
            "   nfvVvW0ar30VJUA6bP7j5SZuFtII2zAvwyxSiNSkZv83GlmjS2uZGwzuL5EGmhQC\n" +
            "   CaU+WfV9LnBx/dWlFneqXEmVcYzj2puYm/wZ04hUU0AijtpjN0rQiFLwjLXg2wOB\n" +
            "   liK9oiMCgYAFQ6J0UzziLoXob/e+7nc34sJgeoQARRavc3IrXIkMO1gSXW+AEppK\n" +
            "   B+yPWpc1Ou9rmC57RXwfvmvXQxf/DMJpkHQqlJUCdnBz8dtbml+OE+T3fSboPl/N\n" +
            "   181ViwdP9YWjAjZzjYWMZJRw1zqgXEm1+XHgW/RvvLUygojJcGL4WA==\n" +
            "   -----END RSA PRIVATE KEY-----";
        String certificate = " -----BEGIN CERTIFICATE-----\n" +
            "   MIIDITCCAgmgAwIBAgIVAM+rkRXEGGvGZrmNueRjztcFoIfkMA0GCSqGSIb3DQEB\n" +
            "   BQUAMEoxCzAJBgNVBAYTAlVTMRAwDgYDVQQKDAdQaXZvdGFsMSkwJwYDVQQDDCBz\n" +
            "   ZXJ2aWNlX3Byb3ZpZGVyX2tleV9jcmVkZW50aWFsczAeFw0xNTA3MTQwNjI3MTVa\n" +
            "   Fw0xNzA3MTMwNjI3MTVaMEoxCzAJBgNVBAYTAlVTMRAwDgYDVQQKDAdQaXZvdGFs\n" +
            "   MSkwJwYDVQQDDCBzZXJ2aWNlX3Byb3ZpZGVyX2tleV9jcmVkZW50aWFsczCCASIw\n" +
            "   DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPLmh5XMtgyy8dh8CMy4cO0CEXhy\n" +
            "   fbIykKTVdGlbDo5SpXu4oCTDWVbc49dVJAr1XIzX1BCoGzP3NDA6aDLedKDg/fWF\n" +
            "   GDcED4ZeGcjnAd+OEadRajNrds8xnmJv2KMfEidm2HAOhejQXOj8zkfWNnZhyAkZ\n" +
            "   3nyz/jcGeYSdj6o3OzJTZ+0sd7jRkOxHDxymxa6uAMFBZF2zZyKenDiQ34SA/NX3\n" +
            "   n39Bwv6GAdVmhATpb5nWTjGEDYbT6TBdY1tPG7wYTbWsHn+uFpRgIGBnRBOjL2G1\n" +
            "   Ns7OCH86q7QG0nYz2emQvEiHzMDO2fI4glrletAzpjEX6CvPDxZ8aOTBnyUCAwEA\n" +
            "   ATANBgkqhkiG9w0BAQUFAAOCAQEAxcYE8Haw1enVMqUtdBOmvCg5ZijVMceVH2Zn\n" +
            "   WJNVqRe62BWySRNE17O0qE2Gj8J8fRtDmzfdDXPhAGksS1dxqfcteiOuPpTaDdWB\n" +
            "   7BbTe4ydojkpFb1FQD0uGx8M6NheaGWMDIRUW2h2zDtXMFr+1IcSMoaGy5siSEej\n" +
            "   tmZPCyoRVUnzDTNArpodjGdEvshKDZI7T9EGob2GQe6ETkEjN073/7tqIAXN0XXp\n" +
            "   eZllc4JUpb8FcvtlU86N4CFvEwl9dzKnzDkw7L4oO8+8CkERAXIg3AWN1aBLeALi\n" +
            "   OesMjbUOhJMg6Caa0/Kf95Yv9DRYfHXpv5qyqob5q8e31YQ82w==\n" +
            "   -----END CERTIFICATE-----";
        String password = "password";

        keyManager = new SamlLoginServerKeyManager(key, password, certificate);
        System.out.println("keyManager credentials= " + Arrays.toString(keyManager.getAvailableCredentials().toArray()));

    }
}
