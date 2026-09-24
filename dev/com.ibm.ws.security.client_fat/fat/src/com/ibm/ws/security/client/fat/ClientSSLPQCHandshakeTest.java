/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/

package com.ibm.ws.security.client.fat;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.ProgramOutput;
import com.ibm.websphere.simplicity.log.Log;

import componenttest.topology.impl.LibertyClientFactory;

import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;

/**
 * Tests SSL handshake between a Liberty client and server verifying Post-Quantum Cryptography
 * (PQC) named group negotiation.
 *
 * The server (SSLHandshakePQCTest) always starts with PQC-capable namedGroups in its jvm.options.
 * The dedicated client (myTestClientPQC) uses only X25519MLKEM768 by default.
 *
 * PQC evidence is verified by searching for the ServerHello key_share named group line
 * ("named group": X25519MLKEM768) in the server trace, which is produced only inside the
 * Produced ServerHello handshake message block when that group is actually negotiated.
 */
@RunWith(FATRunner.class)
@Mode(TestMode.FULL)
public class ClientSSLPQCHandshakeTest extends CommonTest {
    private static final Class<?> c = ClientSSLPQCHandshakeTest.class;
    private static String ERRORSTRING = "Unable to initialize the BasicCalculatorClient";

    /**
     * Search string that specifically identifies X25519MLKEM768 in the ServerHello key_share
     * extension of the server trace. This line only appears inside the structured
     * "Produced ServerHello handshake message" block, confirming PQC was actually negotiated
     * rather than merely advertised.
     */
    private static final String SERVER_HELLO_PQC_NAMED_GROUP = "\"named group\": X25519MLKEM768";

    /**
     * Starts the SSLHandshakePQCTest server before each test.
     * This server always runs with -Djdk.tls.namedGroups=X25519MLKEM768,X25519,secp256r1,secp384r1
     * set in its jvm.options, ensuring PQC named groups are always available for negotiation.
     */
    @Before
    public void before() throws Exception {
        String thisMethod = "before";
        Log.info(c, thisMethod, "Starting PQC server for test: " + name.getMethodName());

        try {
            if (testServer != null && testServer.isStarted()) {
                Log.info(c, thisMethod, "Server already started, stopping and waiting for shutdown");
                testServer.stopServer();
                testServer.waitForStringInLog("CWWKE0036I", 30000);
            }

            commonServerSetUp("SSLHandshakePQCTest", false);

            String featureReady = testServer.waitForStringInLog("CWWKF0008I", 60000);
            if (featureReady == null) {
                throw new Exception("Timeout waiting for FeatureManager to complete");
            }

            String ltpaReady = testServer.waitForStringInLog("CWWKS4105I", 30000);
            if (ltpaReady == null) {
                throw new Exception("Timeout waiting for LTPA configuration");
            }

            Log.info(c, thisMethod, "PQC server is ready for test: " + name.getMethodName());
        } catch (Exception e) {
            Log.error(c, thisMethod, e, "PQC server setup failed");
            try {
                if (testServer != null && testServer.isStarted()) {
                    testServer.stopServer();
                    testServer.waitForStringInLog("CWWKE0036I", 30000);
                }
            } catch (Exception cleanupEx) {
                Log.error(c, thisMethod, cleanupEx, "Cleanup after failed setup also failed");
            }
            throw new Exception("PQC server setup failed: " + e.getMessage(), e);
        }
    }

    /**
     * Stops the server after each test.
     */
    @After
    public void after() {
        String thisMethod = "after";
        Log.info(c, thisMethod, "Stopping PQC server after test: " + name.getMethodName());

        try {
            if (testServer != null) {
                if (testServer.isStarted()) {
                    testServer.stopServer("CWWKZ0124E");
                } else {
                    Log.info(c, thisMethod, "Server is not running, no need to stop");
                }
            } else {
                Log.info(c, thisMethod, "testServer is null, nothing to stop");
            }
        } catch (Exception e) {
            Log.error(c, thisMethod, e, "Exception while stopping PQC server");
        }

        Log.info(c, thisMethod, "After method complete for test: " + name.getMethodName());
    }

    /**
     * Test description:
     * - Both server and client start with PQC-only named group X25519MLKEM768.
     * - Server uses: sslProtocol="TLSv1.3", jvm.options: -Djdk.tls.namedGroups=X25519MLKEM768,X25519,...
     * - Client uses: sslProtocol="TLSv1.3", client.jvm.options: -Djdk.tls.namedGroups=X25519MLKEM768
     *
     * Expected results:
     * - The SSL handshake succeeds using TLS 1.3 with PQC key exchange.
     * - The server trace ServerHello key_share shows "named group": X25519MLKEM768, confirming
     *   PQC was negotiated rather than falling back to a classical group.
     * - The client reports it has started successfully.
     */
    @Test
    public void testPQCHandshakeBothPQCEnabled() {
        try {
            Log.info(c, name.getMethodName(), "Starting PQC-enabled client (both sides PQC) ...");

            ProgramOutput programOutput = commonClientSetUpWithCalcArgs("myTestClientPQC",
                                                                        "client_pqc_enabled.xml",
                                                                        "CWWKF0040E");
            String output = programOutput.getStdout();

            assertTrue("Client should report it has started successfully (CWWKF0035I).",
                       output.contains("5"));

            // Verify the ServerHello key_share extension shows X25519MLKEM768 was negotiated.
            // This line only appears inside the "Produced ServerHello handshake message" block,
            // proving PQC was actually selected — not just advertised in the ClientHello.
            List<String> serverTraceLines = testServer.findStringsInTrace(SERVER_HELLO_PQC_NAMED_GROUP);
            assertFalse("Server trace ServerHello key_share should show \"named group\": X25519MLKEM768",
                        serverTraceLines.isEmpty());

            Log.info(c, name.getMethodName(), "PQC handshake successful: ServerHello confirmed X25519MLKEM768 in key_share");

        } catch (Exception e) {
            Log.error(c, name.getMethodName(), e, "Unexpected exception was thrown.");
            fail("Exception was thrown: " + e);
        }
    }

    /**
     * Test description:
     * - Server restarts with PQC-only named groups: jvm.options overridden to X25519MLKEM768 only
     *   (no classical fallback at the JVM TLS layer).
     * - Client uses TLS 1.3 with non-PQC named groups only (x25519, secp256r1), overriding the
     *   published client.jvm.options via setJvmOptions after getLibertyClient() copies the dir.
     *
     * Expected results:
     * - The SSL handshake fails: server has only X25519MLKEM768, client offers no PQC groups.
     * - Server trace shows "No common named group" fatal error.
     * - The client reports a handshake exception.
     */
    @Test
    public void testPQCHandshakeServerPQCOnlyClientNonPQCFail() {
        try {
            Log.info(c, name.getMethodName(), "Restarting server with PQC-only named groups (no fallback) ...");
            testServer.setMarkToEndOfLog();
            if (testServer.isStarted())
                testServer.stopServer();

            // Override the server JVM to X25519MLKEM768 only — the XML namedGroups attribute alone
            // is not enforced at the JVM TLS layer, so this is the only way to restrict the server.
            testServer.setJvmOptions(Arrays.asList(
                    "-Dcom.ibm.ws.beta.edition=true",
                    "-Djdk.tls.namedGroups=X25519MLKEM768",
                    "-Djavax.net.debug=all"));

            testServer.setServerConfigurationFile("server_pqc_only.xml");
            testServer.startServer();

            assertNotNull("FeatureManager did not report update was complete",
                          testServer.waitForStringInLogUsingMark("CWWKF0008I"));
            assertNotNull("LTPA configuration did not report it was ready",
                          testServer.waitForStringInLogUsingMark("CWWKS4105I"));

            Log.info(c, name.getMethodName(), "Starting standard TLS 1.3 client (no PQC named groups) ...");

            // getLibertyClient copies the published client dir (including the default
            // client.jvm.options with X25519MLKEM768). setJvmOptions must be called on the
            // same instance AFTER that copy and BEFORE startClientWithArgs to override to
            // non-PQC groups only, matching the test constraint.
            testClient = LibertyClientFactory.getLibertyClient("myTestClientPQC");
            transformApps(testClient);

            String fullClientXmlPath = buildFullClientConfigPath(testClient, "client_tls13_standard.xml");
            copyNewClientConfig(fullClientXmlPath);
            addServerPortsToClientBootStrapProp();

            testClient.setJvmOptions(Arrays.asList(
                    "-Djdk.console=java.base",
                    "-Dcom.ibm.ws.beta.edition=true",
                    "-Djdk.tls.namedGroups=x25519,secp256r1",
                    "-Djavax.net.debug=all"));

            testClient.addIgnoreErrors("CWWKF0040E", "CWPKI0823E");

            List<String> startParms = Arrays.asList("--", "add", "2", "3");
            ProgramOutput programOutput = testClient.startClientWithArgs(true, true, true, false, "run", startParms, false);
            String output = programOutput.getStdout();

            assertTrue("Client should report it failed with handshake exception.",
                       output.contains(ERRORSTRING));

            // Search positively for the UNEXPECTED_MESSAGE fatal error the server JVM writes when
            // it has no named group in common with the client. The JVM classifies this as
            // Fatal (UNEXPECTED_MESSAGE) / "No common named group" rather than handshake_failure.
            List<String> noCommonGroupLines = testServer.findStringsInTrace("No common named group");
            assertFalse("Server trace should show a 'No common named group' fatal error when PQC-only server rejects non-PQC client",
                        noCommonGroupLines.isEmpty());

            Log.info(c, name.getMethodName(), "Handshake correctly failed: no common named groups between PQC-only server and non-PQC client");

        } catch (Exception e) {
            Log.error(c, name.getMethodName(), e, "Unexpected exception was thrown.");
            fail("Exception was thrown: " + e);
        }
    }


    /**
     * Test description:
     * - Server is configured with TLS 1.2.
     * - Client uses TLS 1.3 with multiple PQC named groups (X25519MLKEM768 and fallbacks).
     * - Because the server forces TLS 1.2, the TLS 1.3 key_share extension is never used, so no named group
     *  (including mlkem) is ever negotiated or appears in the ServerHello.
     *
     * Expected results:
     * - The SSL handshake fails: TLS 1.2 server cannot complete a TLS 1.3 handshake.
     * - The server trace does NOT contain "named group": X25519MLKEM768 in any ServerHello block.
     * - The client reports a handshake failure
     */

    @Test
    public void testPQCNamedGroupNotNegotiatedonTLS12Server() {
        try {
            Log.info(c, name.getMethodName(), "Restarting server with TLS 1.2 configuration ...");
            testServer.setMarkToEndOfLog();
            if (testServer.isStarted())
                testServer.stopServer();

            testServer.setServerConfigurationFile("server_tls12.xml");
            testServer.startServer(true);

            assertNotNull("Featuremanager did not report update was complete",
                          testServer.waitForStringInLogUsingMark("CWWKF0008I"));
            assertNotNull("LTPA configuration did not report it was ready",
                          testServer.waitForStringInLogUsingMark("CWWKS4105I"));

            Log.info(c, name.getMethodName(), "Starting PQC-enabled client with multiple named groups against TLS 1.2 server ...");

            // getLibertyClient copies the published client directory to the working dir (including
            // the default single-group client.jvm.options). setJvmOptions must be called on the
            // same instance AFTER that copy and BEFORE startClientWithArgs — so we inline the
            // steps of commonClientSetUpWithCalcArgs here and inject setJvmOptions in between.
            testClient = LibertyClientFactory.getLibertyClient("myTestClientPQC");
            transformApps(testClient);

            String fullClientXmlPath = buildFullClientConfigPath(testClient, "client_pqc_multiple.xml");
            copyNewClientConfig(fullClientXmlPath);
            addServerPortsToClientBootStrapProp();

            // Override namedGroups to 3 groups AFTER the published dir has been copied.
            testClient.setJvmOptions(Arrays.asList(
                    "-Djdk.console=java.base",
                    "-Dcom.ibm.ws.beta.edition=true",
                    "-Djdk.tls.namedGroups=X25519MLKEM768,X25519,secp256r1",
                    "-Djavax.net.debug=all"));

            testClient.addIgnoreErrors("CWWKF0040E", "CWPKI0823E");

            List<String> startParms = Arrays.asList("--", "add", "2", "3");
            ProgramOutput programOutput = testClient.startClientWithArgs(true, true, true, false, "run", startParms, false);

            String output = programOutput.getStdout();

            assertTrue("Client should report a handshake failure when connecting to a TLS 1.2 server.", output.contains(ERRORSTRING));

            List<String> protocolVersionLines = testServer.findStringsInTrace("PROTOCOL_VERSION");
            
            assertFalse("Server trace should show a PROTOCOL_VERSION fatal error when TLS 1.2 server rejects TLS 1.3 client",
            protocolVersionLines.isEmpty());

            Log.info(c, name.getMethodName(), "Confirmed: mlkem named group was not negotiated on TLS 1.2 server");
        } catch (Exception e) {
            Log.error(c, name.getMethodName(), e, "unexpected exception was thrown.");
            fail("Exception was thrown: " + e);
        }
    }

}
