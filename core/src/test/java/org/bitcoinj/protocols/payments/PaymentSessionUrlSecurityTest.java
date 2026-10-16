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

import com.google.protobuf.ByteString;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.protobuf.payments.Protos;
import org.bitcoinj.uri.BitcoinURI;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.URL;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * SSRF regression tests for BIP70 payment and payment-request URLs (CVE-2026-111210).
 */
public class PaymentSessionUrlSecurityTest {
    private static final String[] ALLOWED_URLS = {
            "http://192.0.2.1/",
            "https://192.0.2.1/invoice",
            "http://203.0.113.5:8443/pay",
            "https://[2001:db8::1]/pay",
            "http://8.8.8.8/",
            "http://11.0.0.1/",
            "http://172.15.255.255/",
            "http://172.32.0.1/",
            "http://192.167.0.1/",
            "http://192.169.0.1/",
            "http://169.255.1.1/",
            "https://198.51.100.20/request",
            "http://user:pass@192.0.2.1/pay",
            "http://[::8.8.8.8]/",
            "http://[::ffff:8.8.8.8]/",
            "http://[64:ff9b::8.8.8.8]/",
            "http://[2001:db8::1]/",
            "http://[fb00::1]/"
    };

    private static final String[] DISALLOWED_URLS = {
            "file:///etc/passwd",
            "file://127.0.0.1/etc/passwd",
            "ftp://192.0.2.1/file",
            "jar:http://192.0.2.1/foo.jar!/",
            "gopher://192.0.2.1/",
            "dict://127.0.0.1:11211/",
            "netdoc:///etc/passwd",
            "http://127.0.0.1/",
            "http://127.0.0.1:8080/latest",
            "http://127.0.0.0/",
            "http://127.255.255.255/",
            "http://127.1/",
            "http://2130706433/",
            "http://localhost/",
            "http://localhost./",
            "http://127.0.0.1.nip.io/",
            "HTTP://127.0.0.1/x",
            "http://foo:bar@127.0.0.1/",
            "http://[::1]/",
            "http://[::1]:8080/",
            "http://0.0.0.0/",
            "http://0/",
            "http://[::]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/",
            "http://169.254.0.0/",
            "http://169.254.255.255/",
            "http://[fe80::1]/",
            "http://[febf::1]/",
            "http://10.0.0.1/",
            "http://10.0.0.0/",
            "http://10.255.255.255/",
            "http://172.16.0.1/",
            "http://172.16.0.0/",
            "http://172.31.255.255/",
            "http://192.168.0.1/",
            "http://192.168.1.1/",
            "http://192.168.0.0/",
            "http://192.168.255.255/",
            "http://[fc00::1]/",
            "http://[fd00::1]/",
            "http://[fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/",
            "http://[fec0::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[::ffff:10.1.2.3]/",
            "http://[::ffff:192.168.1.20]/",
            "http://[::ffff:172.16.5.5]/",
            "http://[::7f00:1]/",
            "http://[64:ff9b::169.254.169.254]/latest/meta-data/",
            "http://[64:ff9b::a9fe:a9fe]/",
            "http://[64:ff9b:1:a9fe:a9:fe00::]/",
            "http://224.0.0.1/",
            "http://[ff02::1]/",
            "http://",
            "http:///path",
            "not a url",
            "http://no-such-host.invalid/pay",
            "https://2001:db8::1/"
    };

    private Transaction tx;

    @Before
    public void setUp() {
        Context.propagate(new Context());
        ECKey key = new ECKey();
        tx = new Transaction();
        TransactionOutput output = new TransactionOutput(tx, Coin.COIN, key);
        tx.addOutput(output);
        tx.addInput(new TransactionInput(tx, output.getScriptBytes(), TransactionOutPoint.UNCONNECTED));
    }

    @Test
    public void allowsPublicHttpAndHttpsTargets() throws Exception {
        for (String url : ALLOWED_URLS) {
            PaymentSession.checkPaymentUrl(url);
            PaymentSession.checkPaymentRequestUrl(url);
            // The connection path re-validates URL.toString() immediately before openConnection().
            PaymentSession.checkPaymentUrl(new URL(url).toString());
            assertFalse(url, PaymentSession.isDisallowedPaymentAddress(InetAddress.getByName(hostOf(url))));
        }
        assertFalse(PaymentSession.isDisallowedPaymentAddress(InetAddress.getByName("64:ff9b::8.8.8.8")));
    }

    @Test
    public void rejectsDisallowedPaymentAndRequestUrls() {
        for (String url : DISALLOWED_URLS) {
            assertPaymentUrlRejected(url);
            assertPaymentRequestUrlRejected(url);
        }
    }

    @Test
    public void rejectsMalformedNat64LocalPrefix() throws Exception {
        byte[] malformedU = new byte[] {
                0x00, 0x64, (byte) 0xff, (byte) 0x9b, 0x00, 0x01,
                (byte) 0xa9, (byte) 0xfe, 0x01, (byte) 0xa9, (byte) 0xfe,
                0, 0, 0, 0, 0
        };
        assertTrue(PaymentSession.isDisallowedPaymentAddress(InetAddress.getByAddress(malformedU)));
    }

    @Test
    public void sendPaymentDoesNotContactDisallowedPaymentUrl() throws Exception {
        for (String paymentUrl : new String[] {
                "http://127.0.0.1/pay",
                "http://169.254.169.254/latest/meta-data/",
                "http://10.1.2.3/admin",
                "http://192.168.1.1/",
                "http://[::1]/",
                "http://[fc00::1]/",
                "file:///etc/passwd",
                "ftp://192.0.2.1/file"
        }) {
            SinkCapturingSession session = sessionWithPaymentUrl(paymentUrl);
            try {
                session.sendPayment(Collections.singletonList(tx), null, null).get();
                fail("expected InvalidPaymentURL for " + paymentUrl);
            } catch (ExecutionException e) {
                assertTrue(paymentUrl + " cause " + e.getCause(),
                        e.getCause() instanceof PaymentProtocolException.InvalidPaymentURL);
                assertFalse(paymentUrl, session.sinkCalled);
            }
        }
    }

    @Test
    public void sendPaymentAcceptsPublicPaymentUrl() throws Exception {
        SinkCapturingSession session = sessionWithPaymentUrl("https://203.0.113.9/pay");
        CompletableFuture<PaymentProtocol.Ack> ack = session.sendPayment(Collections.singletonList(tx), null, null);
        ack.get();
        assertTrue(session.sinkCalled);
    }

    @Test
    public void createFromUrlRejectsDisallowedRequestUrl() throws Exception {
        for (String url : new String[] {
                "http://127.0.0.1/pr",
                "http://169.254.169.254/latest/meta-data/",
                "http://10.0.0.5/pr",
                "http://[::1]/pr",
                "file:///etc/passwd",
                "ftp://192.0.2.1/pr"
        }) {
            try {
                PaymentSession.createFromUrl(url, false);
                fail("expected InvalidPaymentRequestURL for " + url);
            } catch (PaymentProtocolException.InvalidPaymentRequestURL expected) {
                // Rejected before a connection is attempted.
            }
        }
    }

    @Test
    public void createFromBitcoinUriRejectsDisallowedRequestUrl() throws Exception {
        for (String requestUrl : new String[] {
                "http://127.0.0.1/pr",
                "http://169.254.169.254/latest/meta-data/",
                "http://192.168.0.8/pr",
                "file:///etc/passwd"
        }) {
            BitcoinURI uri = BitcoinURI.of("bitcoin:?r=" + requestUrl);
            try {
                PaymentSession.createFromBitcoinUri(uri, false);
                fail("expected InvalidPaymentRequestURL for " + requestUrl);
            } catch (PaymentProtocolException.InvalidPaymentRequestURL expected) {
                // Rejected before a connection is attempted.
            }
        }
    }

    private static void assertPaymentUrlRejected(String url) {
        try {
            PaymentSession.checkPaymentUrl(url);
            fail("expected InvalidPaymentURL for " + url);
        } catch (PaymentProtocolException.InvalidPaymentURL expected) {
            // fail closed
        } catch (PaymentProtocolException e) {
            fail(url + " threw " + e.getClass().getName());
        }
    }

    private static void assertPaymentRequestUrlRejected(String url) {
        try {
            PaymentSession.checkPaymentRequestUrl(url);
            fail("expected InvalidPaymentRequestURL for " + url);
        } catch (PaymentProtocolException.InvalidPaymentRequestURL expected) {
            // fail closed
        } catch (PaymentProtocolException e) {
            fail(url + " threw " + e.getClass().getName());
        }
    }

    private static String hostOf(String url) throws Exception {
        String host = new URL(url).getHost();
        if (host.startsWith("[") && host.endsWith("]"))
            host = host.substring(1, host.length() - 1);
        return host;
    }

    private SinkCapturingSession sessionWithPaymentUrl(String paymentUrl) throws PaymentProtocolException {
        Protos.Output output = Protos.Output.newBuilder()
                .setAmount(Coin.COIN.getValue())
                .setScript(ByteString.copyFrom(tx.getOutput(0).getScriptBytes()))
                .build();
        Protos.PaymentDetails details = Protos.PaymentDetails.newBuilder()
                .setNetwork("test")
                .setTime(TimeUtils.currentTime().getEpochSecond())
                .setPaymentUrl(paymentUrl)
                .addOutputs(output)
                .build();
        Protos.PaymentRequest request = Protos.PaymentRequest.newBuilder()
                .setPaymentDetailsVersion(1)
                .setPkiType("none")
                .setSerializedPaymentDetails(details.toByteString())
                .build();
        return new SinkCapturingSession(request);
    }

    private static final class SinkCapturingSession extends PaymentSession {
        private boolean sinkCalled;

        private SinkCapturingSession(Protos.PaymentRequest request) throws PaymentProtocolException {
            super(request, false);
        }

        @Override
        protected CompletableFuture<PaymentProtocol.Ack> sendPayment(URL url, Protos.Payment payment) {
            sinkCalled = true;
            return CompletableFuture.completedFuture(null);
        }
    }
}
