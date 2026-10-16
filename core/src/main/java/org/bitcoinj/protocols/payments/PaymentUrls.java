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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Validates BIP-70 URLs before {@link URL#openConnection()}.
 *
 * <p>Only {@code http} and {@code https} are allowed, and only when every resolved address is a public unicast
 * address. Loopback, link-local (including cloud metadata), private, and other non-routable targets are rejected.
 * Redirects are not followed. See CVE-2026-111210.</p>
 */
@SuppressWarnings("deprecation") // BIP-70 and PaymentProtocolException are deprecated on this branch.
final class PaymentUrls {
    private PaymentUrls() {
    }

    /**
     * Parses {@code spec} and rejects schemes and hosts that must not be contacted.
     */
    static URL parseAndCheck(String spec) throws PaymentProtocolException.InvalidPaymentURL {
        if (spec == null || spec.isEmpty())
            throw new PaymentProtocolException.InvalidPaymentURL("Payment URL is missing");
        try {
            URL url = new URL(spec);
            check(url);
            return url;
        } catch (MalformedURLException e) {
            throw new PaymentProtocolException.InvalidPaymentURL(e);
        }
    }

    /**
     * Rejects schemes other than http/https and hosts that resolve to a non-public address.
     * A name is rejected when any of its records is blocked.
     */
    static void check(URL url) throws PaymentProtocolException.InvalidPaymentURL {
        if (url == null)
            throw new PaymentProtocolException.InvalidPaymentURL("Payment URL is missing");
        String protocol = url.getProtocol();
        if (!"http".equals(protocol) && !"https".equals(protocol))
            throw new PaymentProtocolException.InvalidPaymentURL("Payment URL scheme is not allowed");
        String host = url.getHost();
        if (host == null || host.isEmpty())
            throw new PaymentProtocolException.InvalidPaymentURL("Payment URL is missing a host");
        final InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new PaymentProtocolException.InvalidPaymentURL(e);
        }
        if (addresses.length == 0)
            throw new PaymentProtocolException.InvalidPaymentURL("Payment URL host could not be resolved");
        for (InetAddress address : addresses) {
            if (isBlockedAddress(address))
                throw new PaymentProtocolException.InvalidPaymentURL("Payment URL host is not a public address");
        }
    }

    /**
     * Opens an HTTP(S) connection to a URL that has passed {@link #check(URL)}.
     * Automatic redirects are disabled so a public URL cannot bounce the request onto a blocked host.
     */
    static HttpURLConnection open(URL url) throws IOException, PaymentProtocolException.InvalidPaymentURL {
        check(url);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);
        return connection;
    }

    private static boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress())
            return true;
        byte[] raw = address.getAddress();
        if (raw.length == 4)
            return isBlockedIpv4(raw);
        if (raw.length == 16)
            return isBlockedIpv6(raw);
        return true;
    }

    private static boolean isBlockedIpv4(byte[] raw) {
        int b0 = raw[0] & 0xff;
        int b1 = raw[1] & 0xff;
        int b2 = raw[2] & 0xff;
        int b3 = raw[3] & 0xff;
        // 0.0.0.0/8 ("this network") is not a public payment target; 0.0.0.0 reaches the local stack.
        if (b0 == 0)
            return true;
        // Limited broadcast.
        return b0 == 255 && b1 == 255 && b2 == 255 && b3 == 255;
    }

    private static boolean isBlockedIpv6(byte[] raw) {
        int b0 = raw[0] & 0xff;
        // Unique local addresses (fc00::/7), the IPv6 private range. InetAddress.isSiteLocalAddress does not cover it.
        if ((b0 & 0xfe) == 0xfc)
            return true;
        // IPv4-mapped and IPv4-compatible forms. getAllByName usually unwraps these to Inet4Address already.
        if (isIpv4Embedded(raw)) {
            byte[] v4 = new byte[] { raw[12], raw[13], raw[14], raw[15] };
            try {
                return isBlockedAddress(InetAddress.getByAddress(v4));
            } catch (UnknownHostException e) {
                return true;
            }
        }
        return false;
    }

    /** ::ffff:0:0/96 (IPv4-mapped) and the deprecated ::/96 IPv4-compatible form. */
    private static boolean isIpv4Embedded(byte[] raw) {
        for (int i = 0; i < 10; i++) {
            if (raw[i] != 0)
                return false;
        }
        return (raw[10] == (byte) 0xff && raw[11] == (byte) 0xff)
                || (raw[10] == 0 && raw[11] == 0);
    }
}
