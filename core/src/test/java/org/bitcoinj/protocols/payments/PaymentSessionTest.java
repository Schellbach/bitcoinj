/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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
import org.bitcoinj.protobuf.payments.Protos;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.TrustStoreLoader;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.uri.BitcoinURI;
import org.bitcoinj.utils.ListenableCompletableFuture;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.bitcoinj.base.Coin.COIN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PaymentSessionTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    /** Public https payment URL. Must stay globally routable so the SSRF check allows the send. */
    private static final String simplePaymentUrl = "https://1.1.1.1/";
    private static final String paymentRequestMemo = "send coinz noa plz kthx";
    private static final String paymentMemo = "take ze coinz";
    private static final ByteString merchantData = ByteString.copyFromUtf8("merchant data");
    private static final Instant time = TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS);
    private ECKey serverKey;
    private Transaction tx;
    private TransactionOutput outputToMe;
    private final Coin amount = COIN;

    @Before
    public void setUp() {
        Context.propagate(new Context());
        serverKey = new ECKey();
        tx = new Transaction();
        outputToMe = new TransactionOutput(tx, amount, serverKey);
        tx.addOutput(outputToMe);
    }

    @Test
    public void testSimplePayment() throws Exception {
        // Create a PaymentRequest and make sure the correct values are parsed by the PaymentSession.
        MockPaymentSession paymentSession = new MockPaymentSession(newSimplePaymentRequest("test"));
        assertEquals(paymentRequestMemo, paymentSession.getMemo());
        assertEquals(amount, paymentSession.getValue());
        assertEquals(simplePaymentUrl, paymentSession.getPaymentUrl());
        assertEquals(time, paymentSession.time());
        assertTrue(paymentSession.getSendRequest().tx.equals(tx));
        assertFalse(paymentSession.isExpired());

        // Send the payment and verify that the correct information is sent.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(tx, outputToMe.getScriptBytes(), TransactionOutPoint.UNCONNECTED));
        ArrayList<Transaction> txns = new ArrayList<>();
        txns.add(tx);
        Address refundAddr = serverKey.toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
        paymentSession.sendPayment(txns, refundAddr, paymentMemo);
        assertEquals(1, paymentSession.getPaymentLog().size());
        assertEquals(simplePaymentUrl, paymentSession.getPaymentLog().get(0).getUrl().toString());
        Protos.Payment payment = paymentSession.getPaymentLog().get(0).getPayment();
        assertEquals(paymentMemo, payment.getMemo());
        assertEquals(merchantData, payment.getMerchantData());
        assertEquals(1, payment.getRefundToCount());
        assertEquals(amount.value, payment.getRefundTo(0).getAmount());
        TransactionOutput refundOutput = new TransactionOutput(null, amount, refundAddr);
        ByteString refundScript = ByteString.copyFrom(refundOutput.getScriptBytes());
        assertTrue(refundScript.equals(payment.getRefundTo(0).getScript()));
    }

    @Test
    public void testDefaults() throws Exception {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setTime(time.getEpochSecond())
                .addOutputs(outputBuilder)
                .build();
        Protos.PaymentRequest paymentRequest = Protos.PaymentRequest.newBuilder()
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
        MockPaymentSession paymentSession = new MockPaymentSession(paymentRequest);
        assertEquals(Coin.ZERO, paymentSession.getValue());
        assertNull(paymentSession.getPaymentUrl());
        assertNull(paymentSession.getMemo());
    }

    @Test
    public void testExpiredPaymentRequest() throws PaymentProtocolException {
        MockPaymentSession paymentSession = new MockPaymentSession(newExpiredPaymentRequest());
        assertTrue(paymentSession.isExpired());
        // Send the payment and verify that an exception is thrown.
        // Add a dummy input to tx so it is considered valid.
        tx.addInput(new TransactionInput(tx, outputToMe.getScriptBytes(), TransactionOutPoint.UNCONNECTED));
        ArrayList<Transaction> txns = new ArrayList<>();
        txns.add(tx);

        CompletableFuture<PaymentProtocol.Ack> ack = paymentSession.sendPayment(txns, null, null);
        try {
            ack.get();
        } catch (ExecutionException e) {
            if (e.getCause() instanceof PaymentProtocolException.Expired) {
                PaymentProtocolException.Expired cause = (PaymentProtocolException.Expired) e.getCause();
                assertEquals(0, paymentSession.getPaymentLog().size());
                assertEquals(cause.getMessage(), "PaymentRequest is expired");
                return;
            }
        } catch (InterruptedException e) {
            // Ignore
        }
        fail("Expected exception due to expired PaymentRequest");
    }

    @Test
    public void testSendPaymentRejectsBlockedPaymentUrls() throws Exception {
        tx.addInput(new TransactionInput(tx, outputToMe.getScriptBytes(), TransactionOutPoint.UNCONNECTED));
        String[] blocked = {
                "file:///etc/passwd",
                "ftp://1.1.1.1/file",
                "jar:file:///tmp/x.jar!/y",
                "gopher://1.1.1.1/",
                "http://127.0.0.1/pay",
                "http://127.0.0.1:8332/pay",
                "https://127.0.0.1/pay",
                "http://localhost/pay",
                "http://[::1]/pay",
                "http://10.1.2.3/pay",
                "http://172.16.0.1/pay",
                "http://192.168.1.1/pay",
                "http://169.254.169.254/latest/meta-data/",
                "http://0.0.0.0/",
                "http://[fc00::1]/",
                "http://[fe80::1]/",
                "http://2130706433/",
                "http://127.1/",
                "http://[::ffff:127.0.0.1]/",
                "http://[::ffff:10.1.2.3]/",
                "http://[::ffff:169.254.169.254]/"
        };
        for (String blockedUrl : blocked) {
            PaymentSession session = new PaymentSession(newPaymentRequest(blockedUrl), false);
            CompletableFuture<PaymentProtocol.Ack> ack = session.sendPayment(Collections.singletonList(tx), null, null);
            try {
                ack.get(3, TimeUnit.SECONDS);
                fail("expected blocked payment URL: " + blockedUrl);
            } catch (ExecutionException e) {
                assertTrue(blockedUrl + " -> " + e.getCause(),
                        e.getCause() instanceof PaymentProtocolException.InvalidPaymentURL);
            }
        }
    }

    @Test
    public void testSendPaymentDoesNotConnectToLoopback() throws Exception {
        ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        server.setSoTimeout(300);
        try {
            tx.addInput(new TransactionInput(tx, outputToMe.getScriptBytes(), TransactionOutPoint.UNCONNECTED));
            String url = "http://127.0.0.1:" + server.getLocalPort() + "/pay";
            PaymentSession session = new PaymentSession(newPaymentRequest(url), false);
            CompletableFuture<PaymentProtocol.Ack> ack = session.sendPayment(Collections.singletonList(tx), null, null);
            try {
                ack.get(3, TimeUnit.SECONDS);
                fail("expected blocked loopback payment URL");
            } catch (ExecutionException e) {
                assertTrue(e.getCause() instanceof PaymentProtocolException.InvalidPaymentURL);
            }
            try {
                server.accept();
                fail("payment POST connected to a loopback listener");
            } catch (SocketTimeoutException expected) {
                // The blocked URL never opened a connection.
            }
        } finally {
            server.close();
        }
    }

    @Test
    public void testCreateFromUrlRejectsBlockedTargets() throws Exception {
        String[] blocked = {
                "file:///etc/passwd",
                "file://localhost/etc/passwd",
                "ftp://1.1.1.1/file",
                "jar:http://127.0.0.1!/foo",
                "http://127.0.0.1/request",
                "http://[::1]/request",
                "http://10.0.0.1/",
                "http://192.168.0.1/",
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost/request"
        };
        for (String blockedUrl : blocked) {
            try {
                PaymentSession.createFromUrl(blockedUrl, false);
                fail("expected blocked payment request URL: " + blockedUrl);
            } catch (PaymentProtocolException.InvalidPaymentRequestURL expected) {
                // Rejected before a connection is opened.
            }
        }
    }

    @Test
    public void testCreateFromBitcoinUriRejectsLoopbackPaymentRequest() throws Exception {
        BitcoinURI uri = BitcoinURI.of("bitcoin:?r=http://127.0.0.1/request");
        try {
            PaymentSession.createFromBitcoinUri(uri, false);
            fail("expected blocked r= URL");
        } catch (PaymentProtocolException.InvalidPaymentRequestURL expected) {
            // Rejected before a connection is opened.
        }
    }

    @Test
    public void testPublicHttpPaymentUrlIsStillSubmitted() throws Exception {
        String paymentUrl = "http://1.1.1.1/pay";
        MockPaymentSession paymentSession = new MockPaymentSession(newPaymentRequest(paymentUrl));
        tx.addInput(new TransactionInput(tx, outputToMe.getScriptBytes(), TransactionOutPoint.UNCONNECTED));
        paymentSession.sendPayment(Collections.singletonList(tx), null, paymentMemo);
        assertEquals(1, paymentSession.getPaymentLog().size());
        assertEquals(paymentUrl, paymentSession.getPaymentLog().get(0).getUrl().toString());
    }

    @Test
    @Ignore("certificate expired")
    public void testPkiVerification() throws Exception {
        InputStream in = getClass().getResourceAsStream("pki_test.bitcoinpaymentrequest");
        Protos.PaymentRequest paymentRequest = Protos.PaymentRequest.newBuilder().mergeFrom(in).build();
        PaymentProtocol.PkiVerificationData pkiData = PaymentProtocol.verifyPaymentRequestPki(paymentRequest,
                new TrustStoreLoader.DefaultTrustStoreLoader().getKeyStore());
        assertEquals("www.bitcoincore.org", pkiData.displayName);
        assertEquals("The USERTRUST Network, Salt Lake City, US", pkiData.rootAuthorityName);
    }

    private Protos.PaymentRequest newPaymentRequest(String paymentUrl) {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setAmount(amount.value)
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setNetwork("test")
                .setTime(time.getEpochSecond())
                .setPaymentUrl(paymentUrl)
                .addOutputs(outputBuilder)
                .setMemo(paymentRequestMemo)
                .setMerchantData(merchantData)
                .build();
        return Protos.PaymentRequest.newBuilder()
                .setPaymentDetailsVersion(1)
                .setPkiType("none")
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
    }

    private Protos.PaymentRequest newSimplePaymentRequest(String netID) {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setAmount(amount.value)
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setNetwork(netID)
                .setTime(time.getEpochSecond())
                .setPaymentUrl(simplePaymentUrl)
                .addOutputs(outputBuilder)
                .setMemo(paymentRequestMemo)
                .setMerchantData(merchantData)
                .build();
        return Protos.PaymentRequest.newBuilder()
                .setPaymentDetailsVersion(1)
                .setPkiType("none")
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
    }

    private Protos.PaymentRequest newExpiredPaymentRequest() {
        Protos.Output.Builder outputBuilder = Protos.Output.newBuilder()
                .setAmount(amount.value)
                .setScript(ByteString.copyFrom(outputToMe.getScriptBytes()));
        Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder()
                .setNetwork("test")
                .setTime(time.minusSeconds(10).getEpochSecond())
                .setExpires(time.minusSeconds(1).getEpochSecond())
                .setPaymentUrl(simplePaymentUrl)
                .addOutputs(outputBuilder)
                .setMemo(paymentRequestMemo)
                .setMerchantData(merchantData)
                .build();
        return Protos.PaymentRequest.newBuilder()
                .setPaymentDetailsVersion(1)
                .setPkiType("none")
                .setSerializedPaymentDetails(paymentDetails.toByteString())
                .build();
    }

    private static class MockPaymentSession extends PaymentSession {
        private final ArrayList<PaymentLogItem> paymentLog = new ArrayList<>();

        public MockPaymentSession(Protos.PaymentRequest request) throws PaymentProtocolException {
            super(request);
        }

        public ArrayList<PaymentLogItem> getPaymentLog() {
            return paymentLog;
        }

        @Override
        protected ListenableCompletableFuture<PaymentProtocol.Ack> sendPayment(final URL url, final Protos.Payment payment) {
            paymentLog.add(new PaymentLogItem(url, payment));
            // Return a completed future that has a `null` value. This will satisfy the current tests.
            return ListenableCompletableFuture.completedFuture(null);
        }

        public static class PaymentLogItem {
            private final URL url;
            private final Protos.Payment payment;

            PaymentLogItem(final URL url, final Protos.Payment payment) {
                this.url = url;
                this.payment = payment;
            }

            public URL getUrl() {
                return url;
            }

            public Protos.Payment getPayment() {
                return payment;
            }
        }
    }
}
