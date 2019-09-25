package com.wfc.cert

import com.wfc.cert.OCSP.Companion.getOCSPRespBytes
import com.wfc.cert.OCSP.Companion.isGoodCertificate
import com.wfc.cert.OCSP.Companion.makeOCSPRequest
import com.wfc.cert.OCSP.Companion.makeOCSPResponse
import com.wfc.cert.OCSP.Companion.sendOCSPReq
import junit.framework.Assert.assertEquals
import net.corda.core.internal.div
import net.corda.nodeapi.internal.crypto.X509Utilities
import net.corda.nodeapi.internal.crypto.getSupportedKey
import net.corda.nodeapi.internal.crypto.loadOrCreateKeyStore
import net.corda.nodeapi.internal.crypto.x509
import org.bouncycastle.cert.ocsp.OCSPRespBuilder
import org.junit.Test
import java.nio.file.Path
import java.nio.file.Paths

/**
 * Per README.md of Experimental project, unit tests are disabled.
 * So we need
 * gradlew test -Dexperimental.test.enable
 * In Intellij run configuration, add -Dexperimental.test.enable to VM option for each test.
 */
class OCSPTest {
    private val caCerFolder = Paths.get(System.getProperty("user.home")) / "certs/wfc/dev/cer_20190622"
    private val cerFolder = caCerFolder / "cer"
    private fun caCerFile(name: String): Path = caCerFolder / name
    private fun cerFile(name: String): Path = cerFolder / name

    private val caJKsFolder = Paths.get(System.getProperty("user.home")) / "certs/wfc/dev/certs"
    private val nodeJKSFolder = caJKsFolder / "nodes" / "PartyA"
    private fun caJKSFile(name: String): Path = caJKsFolder / name
    private fun nodeJKSFile(name: String): Path = nodeJKSFolder / name
    private val caStorepass = "trustpass"
    private val caKeypass = "trustpass"
    private val nodeStorepass = "cordacadevpass"
    private val nodeKeypass = "cordacadevpass"

    /**
     * Uses certs from Richard via the CSR process.
     */
    @Test
    fun `create a OCSP request - from cer files`() {
        val caFile = caCerFile("ica1.cer")
        val cerFile = cerFile("partya_identity.cer")
        val caCert = X509Utilities.loadCertificateFromPEMFile(caFile)
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)
        val req = OCSP.makeOCSPRequest(caCert, cert)
    }

    /**
     * Uses certs from JKS files we create via the cert command of the CertGen tool.
     * Since we have private keys of the ca, we will be able to test end-to-end without using url:
     * 1. create req
     * 2. create resp, and
     * 3. parse resp.
     * This test performs step 1.
     */
    @Test
    fun `create a OCSP request - from jks files`() {
        val caJKSFile = caJKSFile("issuingca1.jks")
        val nodeJKSFile = nodeJKSFile("nodekeystore.jks")
        val caKeystore = loadOrCreateKeyStore(caJKSFile, caStorepass)
        val caCert = caKeystore.getCertificate(Common.issuingCAAlias).x509
        val nodeKeystore = loadOrCreateKeyStore(nodeJKSFile, nodeStorepass)
        val nodeCert = nodeKeystore.getCertificate(Common.identityAlias).x509
        val req = makeOCSPRequest(caCert, nodeCert)
    }

    /**
     * This test performs steps 1, 2 and 3.
     */
    @Test
    fun `create a OCSP request, response and validate - from jks files`() {
        // step 1
        val caJKSFile = caJKSFile("issuingca1.jks")
        val nodeJKSFile = nodeJKSFile("nodekeystore.jks")
        val caKeystore = loadOrCreateKeyStore(caJKSFile, caStorepass)
        val caCert = caKeystore.getCertificate(Common.issuingCAAlias).x509
        val nodeKeystore = loadOrCreateKeyStore(nodeJKSFile, nodeStorepass)
        val nodeCert = nodeKeystore.getCertificate(Common.identityAlias).x509
        val req = makeOCSPRequest(caCert, nodeCert)
        // step 2
        val caPrivateKey = caKeystore.getSupportedKey(Common.issuingCAAlias, caKeypass)
        /**
         * Test both positive and negative .
         */
        listOf(true, false).forEach { forceToSuccess ->
            val resp = makeOCSPResponse(caCert, caPrivateKey, req, forceToSuccess)
            // step 3
            val isGoodCertificate = isGoodCertificate(resp, caCert, nodeCert)
            assertEquals(isGoodCertificate, forceToSuccess)
        }
    }

    /**
     * Uses certs from JKS files we create via the cert command of the CertGen tool.
     * This is to test sendOCSPReq(...)
     * 1. create req
     * 2. send req to a responder URL
     * 3. parse resp.
     */
    @Test
    fun `create a OCSP request, send and get response, validate - from jks files`() {
        // step 1
        val caJKSFile = caJKSFile("issuingca1.jks")
        val nodeJKSFile = nodeJKSFile("nodekeystore.jks")
        val caKeystore = loadOrCreateKeyStore(caJKSFile, caStorepass)
        val caCert = caKeystore.getCertificate(Common.issuingCAAlias).x509
        val nodeKeystore = loadOrCreateKeyStore(nodeJKSFile, nodeStorepass)
        val nodeCert = nodeKeystore.getCertificate(Common.identityAlias).x509
        val req = makeOCSPRequest(caCert, nodeCert)
        // step 2
        val url = "http://validator.wellsfargo.com"
//        val url = "http://ocsp.digicert.com"
        val resp = sendOCSPReq(req, url)
        // step 3
        val isGoodCertificate = isGoodCertificate(resp, caCert, nodeCert)

    }

    /**
     * Uses certs from cer from Richard.
     * This is to test sendOCSPReq(...)
     * 1. create req
     * 2. send req to a responder URL
     * 3. parse resp.
     */
    @Test
    fun `create a OCSP request, send and get response, validate`() {
        // step 1
        val caFile = caCerFile("ca5E85A.cer")
//        val caFile = caCerFile("ca4sean_base64.cer")
//        val caFile = caCerFile("ica1.cer")
        val cerFile = cerFile("5E85A.cer")
//        val cerFile = cerFile("sean_base64.cer")
//        val cerFile = cerFile("partya_identity.cer")
        val caCert = X509Utilities.loadCertificateFromPEMFile(caFile)
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)
        val req = makeOCSPRequest(caCert, cert)
        // step 2
        val url = "http://validator.wellsfargo.com"
//        val url = "http://ocsp.digicert.com"
//        val url = "http://ocsp.verisign.com"
//        val url = "http://ocsp.entrust.net"
        val resp = sendOCSPReq(req, url)
//        val resp = sendOCSPReq_1(req, url)
        // step 3
//        val isGoodCertificate = isGoodCertificate(resp, caCert, cert)
//        assertTrue(!isGoodCertificate)
//        assertEquals(resp.status, OCSPRespBuilder.UNAUTHORIZED)

    }

    @Test
    fun `write req and resp to files`() {
        // step 1
        val caFile = caCerFile("ca5E85A.cer")
//        val caFile = caCerFile("ca4sean_base64.cer")
//        val caFile = caCerFile("ica1.cer")
        val cerFile = cerFile("5E85A.cer")
//        val cerFile = cerFile("sean_base64.cer")
//        val cerFile = cerFile("partya_identity.cer")
        val caCert = X509Utilities.loadCertificateFromPEMFile(caFile)
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)
        val req = makeOCSPRequest(caCert, cert)
        val reqFile = cerFile("5E85A.orq").toFile()
        val respFile = cerFile("5E85A_from_digicert.ors").toFile()
        // step 2
//        val url = "http://validator.wellsfargo.com"
        val url = "http://ocsp.digicert.com"
//        val url = "http://ocsp.verisign.com"
//        val url = "http://ocsp.entrust.net"
        val respBytes = getOCSPRespBytes(req, url)

        reqFile.writeBytes(req.encoded)
        respFile.writeBytes(respBytes)
    }
}