/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.protocols.payments;

import org.junit.Test;

import java.net.HttpURLConnection;
import java.net.URL;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

/**
 * Regression coverage for CVE-2026-111210: BIP-70 fetches must not accept non-http(s) schemes or non-public hosts.
 */
public class PaymentUrlsTest {
    @Test
    public void blockedSchemesAreRejected() throws Exception {
        String[] blocked = {
                "file:///etc/passwd",
                "file://localhost/etc/passwd",
                "ftp://1.1.1.1/file",
                "jar:file:///tmp/x.jar!/y",
                "jar:http://1.1.1.1!/foo",
                "gopher://1.1.1.1/",
                "ldap://1.1.1.1/",
                "data:text/plain,hi",
                "javascript:alert(1)",
                "bitcoin:1abc"
        };
        for (String spec : blocked)
            assertBlocked(spec);
    }

    @Test
    public void privateLoopbackAndLinkLocalHostsAreRejected() throws Exception {
        String[] blocked = {
                "http://127.0.0.1/",
                "http://127.0.0.1:8332/pay",
                "https://127.0.0.1/pay",
                "HTTP://127.0.0.1/",
                "http://127.255.255.255/",
                "http://localhost/",
                "http://[::1]/",
                "http://[::1]:80/",
                "http://10.0.0.1/",
                "http://10.255.255.255/",
                "http://172.16.0.1/",
                "http://172.31.255.255/",
                "http://192.168.0.1/",
                "http://192.168.1.1/",
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.1.1/",
                "http://0.0.0.0/",
                "http://0.0.0.1/",
                "http://0/",
                "http://[::]/",
                "http://[fc00::1]/",
                "http://[fd12:3456::1]/",
                "http://[fe80::1]/",
                "http://[fec0::1]/",
                "http://224.0.0.1/",
                "http://255.255.255.255/",
                "http://2130706433/",
                "http://127.1/",
                "http://127.0.1/",
                "http://[::ffff:127.0.0.1]/",
                "http://[::ffff:7f00:1]/",
                "http://[::ffff:10.1.2.3]/",
                "http://[::ffff:169.254.169.254]/",
                "http://[::ffff:192.168.1.1]/",
                "https:///pay",
                "http:///"
        };
        for (String spec : blocked)
            assertBlocked(spec);
    }

    @Test
    public void publicHttpAndHttpsUrlsAreAllowed() throws Exception {
        String[] allowed = {
                "https://1.1.1.1/pay",
                "https://1.1.1.1:443/pay",
                "http://1.1.1.1/pay",
                "http://1.1.1.1:8080/pay",
                "https://8.8.8.8/",
                "https://[2606:4700:4700::1111]/",
                "https://[2001:4860:4860::8888]/dns-query",
                "http://[::ffff:8.8.8.8]/",
                "http://11.0.0.1/",
                "http://172.15.255.255/",
                "http://172.32.0.1/",
                "http://192.167.1.1/",
                "http://169.255.1.1/",
                "https://192.0.2.1/pay?invoice=1"
        };
        for (String spec : allowed) {
            try {
                PaymentUrls.check(new URL(spec));
            } catch (PaymentProtocolException.InvalidPaymentURL e) {
                fail(spec + " should be allowed: " + e.getMessage());
            }
        }
    }

    @Test
    public void publicHttpsConnectionDoesNotFollowRedirects() throws Exception {
        HttpURLConnection connection = PaymentUrls.open(new URL("https://1.1.1.1/pay"));
        try {
            assertFalse(connection.getInstanceFollowRedirects());
            assertEquals("https", connection.getURL().getProtocol());
            assertEquals("1.1.1.1", connection.getURL().getHost());
            assertEquals("/pay", connection.getURL().getPath());
        } finally {
            connection.disconnect();
        }
    }

    private static void assertBlocked(String spec) {
        try {
            PaymentUrls.parseAndCheck(spec);
            fail("expected blocked URL: " + spec);
        } catch (PaymentProtocolException.InvalidPaymentURL expected) {
            // scheme or host rejected
        }
    }
}
