package com.wfc.cert

import net.corda.nodeapi.internal.crypto.X509Utilities
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.cert.ocsp.*
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.cert.X509Certificate
import org.bouncycastle.operator.DigestCalculatorProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.*
import java.lang.IllegalStateException
import java.math.BigInteger
import java.net.*
import java.security.PrivateKey
import java.util.*

/**
 * Refs:
 * https://www.programcreek.com/java-api-examples/?api=org.bouncycastle.cert.ocsp.OCSPReq
 * https://www.programcreek.com/java-api-examples/?code=GluuFederation/oxAuth/oxAuth-master/Server/src/main/java/org/xdi/oxauth/cert/validation/OCSPCertificateVerifier.java
 * This java code has http, and samples for get URL from cert, etc
 * https://www.javatips.net/api/netty-master/netty-4.1/example/src/main/java/io/netty/example/ocsp/OcspUtils.java
 */
class OCSP {
    companion object {
        fun makeOCSPRequest(caCert: X509Certificate, certToCheck: X509Certificate): OCSPReq {
            /**
             * The following together also works in defining digCalcProv.
             * It is good to use strong-typed BouncyCastleProvider instead of "BC".
             * But I don't feel comfortable to keep adding providers if we call it over and over again.
             * Maybe more learning. But for now, I prefer using setProvider.
             * Actually, Corda uses addProvider(...) in ProviderMap.kt.
             */
//            Security.addProvider(BouncyCastleProvider())
//            val digCalcProv: DigestCalculatorProvider = JcaDigestCalculatorProviderBuilder().build()

            /**
             * Not sure how to import BouncyCastleFipsProvider
             * Therefore, the following will err out with
             * java.security.NoSuchProviderException: no such provider: BCFIPS
             * https://www.bouncycastle.org/fips-java/BCFipsIn100.pdf
             */
//            val digCalcProv: DigestCalculatorProvider = JcaDigestCalculatorProviderBuilder().setProvider("BCFIPS").build()

            /**
             * We cannot call setProvider("BC") without earlier calling addProvider(BouncyCastleProvider()) .
             * To combine both, we call setProvider(BouncyCastleProvider())
             */
            val digCalcProv: DigestCalculatorProvider = JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider()).build()
//            val digCalcProv: DigestCalculatorProvider = JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
            val certId: CertificateID = JcaCertificateID(digCalcProv.get(CertificateID.HASH_SHA1), caCert, certToCheck.serialNumber)
            val ocspReqBuilder = OCSPReqBuilder()
            ocspReqBuilder.addRequest(certId)
            /**
             * Test some extensions
             * nonce
             * basic
             */
            val nonce = BigInteger.valueOf(System.currentTimeMillis())
            val ext_nonce = Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, DEROctetString(nonce.toByteArray()))
//            val ext_basic = Extension(OCSPObjectIdentifiers.id_pkix_ocsp_basic, false, DEROctetString(ByteArray(0)))
//            ocspReqBuilder.setRequestExtensions(Extensions(arrayOf(ext_nonce, ext_basic)))
//            ocspReqBuilder.setRequestExtensions(Extensions(arrayOf(ext_nonce)))
            val req = ocspReqBuilder.build()
            return req
        }

        /**
         * This does not apply to our case since we don't sign OCSP requests.
         */
        fun checkForValidRequest(req: OCSPReq) {
            if (!req.isSigned) {
                throw IllegalStateException("Request is not signed.")
            }
            if (!req.isSignatureValid(JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider()).build(req.certs.first()))) {
                throw IllegalStateException("Request signature is not valid.")
            }
        }

        /**
         * OCSPResp(inputStream) results in
         * unknown tag 28 encountered
            java.io.IOException: unknown tag 28 encountered
            at org.bouncycastle.asn1.ASN1InputStream.buildObject(Unknown Source)
            at org.bouncycastle.asn1.ASN1InputStream.readObject(Unknown Source)
            at org.bouncycastle.cert.ocsp.OCSPResp.<init>(Unknown Source)
            at org.bouncycastle.cert.ocsp.OCSPResp.<init>(Unknown Source)
            at org.bouncycastle.cert.ocsp.OCSPResp.<init>(Unknown Source)
        buildObject source code is in
            https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/asn1/ASN1InputStream.java
        The post function here is one example
            https://github.com/beppec56/odf-xades/blob/master/oxsit-custom_it/src/com/yacme/ext/oxsit/cust_it/security/crl/OCSPQuery.java
         */
        //@Throws(IOException::class, ConnectException::class)
        fun sendOCSPReq(req: OCSPReq, url: String): OCSPResp {
            val proxyHost = System.getProperty("http_proxyHost")
            val proxyPort = System.getProperty("http_proxyPort")?.toInt()
            val webProxy = if (proxyHost != null && proxyPort != null) {
                Proxy(Proxy.Type.HTTP, InetSocketAddress(proxyHost, proxyPort))
            } else null
            val bytes = req.encoded
            val conn: HttpURLConnection = (if (webProxy != null) URL(url).openConnection(webProxy) else URL(url).openConnection()) as HttpURLConnection
            conn.setRequestProperty("Content-Type", "application/ocsp-request")
            conn.setRequestProperty("Accept", "application/ocsp-response")
            conn.setRequestProperty("Content-Length", bytes.size.toString())
            conn.doInput = true
            conn.doOutput = true
            conn.useCaches = false
            conn.requestMethod = "POST"
            conn.allowUserInteraction = false
            conn.instanceFollowRedirects = false
            println("${conn.usingProxy()}")
            conn.connect()
//            val outputStream = conn.outputStream
            val outputStream = DataOutputStream(BufferedOutputStream(conn.outputStream))
            outputStream.use {
                it.write(bytes)
                it.flush()
            }
            if (conn.responseCode != HttpURLConnection.HTTP_OK)
                throw ConnectException("OCSP request failed (HTTP ${conn.responseCode}) - ${conn.responseMessage}")
            /**
             * http://validator.wellsfargo.com
             *  returns contentType is text/html; charset=utf-8
             */
            if (conn.contentType == null || !conn.contentType.equals("application/ocsp-response"))
                throw ConnectException("Response MIME type is not application/ocsp-response.")
//            val inputStream = conn.inputStream
//            val inputStream = ASN1InputStream(conn.content as InputStream)
            val inputStream = conn.content as InputStream
            inputStream.use {
                val bytes = it.readBytes()
                return OCSPResp(bytes)
            }

//            try {
////                inputStream.readBytes()
//                return OCSPResp(inputStream.readBytes())
////                return OCSPResp(inputStream)
//            }
//            catch (e: Exception) {
//                // TODO: do we need to do more than just a rethrow?
//                throw e
//            }
//            finally {
//                inputStream.close()
//            }
        }

        fun getOCSPRespBytes(req: OCSPReq, url: String): ByteArray {
            val bytes = req.encoded
            val conn: HttpURLConnection = URL(url).openConnection() as HttpURLConnection
            conn.setRequestProperty("Content-Type", "application/ocsp-request")
            conn.setRequestProperty("Accept", "application/ocsp-response")
            conn.setRequestProperty("Content-Length", bytes.size.toString())
            conn.doInput = true
            conn.doOutput = true
            conn.useCaches = false
            conn.requestMethod = "GET" //"POST"
            conn.allowUserInteraction = false
            conn.instanceFollowRedirects = false
            conn.connect()
//            val outputStream = conn.outputStream
            val outputStream = DataOutputStream(BufferedOutputStream(conn.outputStream))
            outputStream.use {
                it.write(bytes)
                it.flush()
            }
            if (conn.responseCode != HttpURLConnection.HTTP_OK)
                throw ConnectException("OCSP request failed (HTTP ${conn.responseCode}) - ${conn.responseMessage}")
            /**
             * http://validator.wellsfargo.com
             *  returns contentType is text/html; charset=utf-8
             */
//            if (conn.contentType == null || !conn.contentType.equals("application/ocsp-response"))
//                throw ConnectException("Response MIME type is not application/ocsp-response.")
//            val inputStream = conn.inputStream
//            val inputStream = ASN1InputStream(conn.content as InputStream)
            val inputStream = conn.content as InputStream
            inputStream.use {
                val bytes = it.readBytes()
                return bytes
            }
        }

        /**
         * OCSPResp(inputStream) results in
         * unknown tab 28 encountered
            java.io.IOException: unknown tag 28 encountered
            at org.bouncycastle.asn1.ASN1InputStream.buildObject(Unknown Source)
            at org.bouncycastle.asn1.ASN1InputStream.readObject(Unknown Source)
            at org.bouncycastle.cert.ocsp.OCSPResp.<init>(Unknown Source)
            at org.bouncycastle.cert.ocsp.OCSPResp.<init>(Unknown Source)
            at org.bouncycastle.cert.ocsp.OCSPResp.<init>(Unknown Source)
         */
        fun sendOCSPReq_1(req: OCSPReq, url: String): OCSPResp {
            val bytes = req.encoded
            val conn: HttpURLConnection = URL(url).openConnection() as HttpURLConnection
            conn.setRequestProperty("Content-Type", "application/ocsp-request")
            conn.setRequestProperty("Accept", "application/ocsp-response")
            conn.doInput = true
            conn.doOutput = true
            conn.useCaches = false
            val outputStream = conn.outputStream //  DataOutputStream(BufferedOutputStream())
//            val outputStream = DataOutputStream(BufferedOutputStream(conn.outputStream))
//            outputStream.write(bytes)
//            outputStream.flush()
//            outputStream.close()
            try {
                IOUtils.write(bytes, outputStream)
                outputStream.flush()
            }
            finally {
                IOUtils.closeQuietly(outputStream)
            }
            if (conn.responseCode != HttpURLConnection.HTTP_OK)
                throw ConnectException("OCSP request failed (HTTP ${conn.responseCode}) - ${conn.responseMessage}")
            val inputStream = IOUtils.toByteArray(conn.inputStream)
            return OCSPResp(inputStream)
        }

        /**
         * This is to simulate a OCSP responder.
         * @param forceToSuccess to simulate a positive or negative response.
         */
        fun makeOCSPResponse(caCert: X509Certificate, caPrivateKey: PrivateKey, ocspReq: OCSPReq, forceToSuccess: Boolean = true): OCSPResp {
            val digCalcProv: DigestCalculatorProvider = JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider()).build()
            val basicRespBuilder: BasicOCSPRespBuilder = JcaBasicOCSPRespBuilder(caCert.publicKey, digCalcProv.get(RespID.HASH_SHA1))
            val certId: CertificateID = ocspReq.requestList.first().certID
            // some magic ...
            basicRespBuilder.addResponse(certId, CertificateStatus.GOOD)
            val resp: BasicOCSPResp = basicRespBuilder.build(
                    JcaContentSignerBuilder("SHA384withECDSA").setProvider(BouncyCastleProvider()).build(caPrivateKey),
                    arrayOf(JcaX509CertificateHolder(caCert)),
                    Date()
            )
            val respBuilder = OCSPRespBuilder()
            return respBuilder.build(if (forceToSuccess) OCSPRespBuilder.SUCCESSFUL else OCSPRespBuilder.MALFORMED_REQUEST, resp)
//            return respBuilder.build(OCSPRespBuilder.SUCCESSFUL, resp)
            /**
             * It is possible to encode OCSPResp.
             * Then parse the encoded back to OSCPResp.
             */
            /*
            val resp1 = respBuilder.build(if (forceToSuccess) OCSPRespBuilder.SUCCESSFUL else OCSPRespBuilder.MALFORMED_REQUEST, resp)
            return OCSPResp(resp1.encoded)
            */
        }

        fun isGoodCertificate(ocspResp: OCSPResp, caCert: X509Certificate, eeCert: X509Certificate): Boolean {
            val digCalcProv: DigestCalculatorProvider = JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
            /**
             * OCSPRespBuilder.SUCCESSFUL means that the OCSP request worked;
             * it does not mean the certificate is valid
             */
            if (ocspResp.status == OCSPRespBuilder.SUCCESSFUL) {
                val resp: BasicOCSPResp = ocspResp.responseObject as BasicOCSPResp
                // Make sure response is signed by the appropriate CA
                if (resp.isSignatureValid(JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider()).build(caCert.publicKey))) {
                    return resp.responses.first().certID.matchesIssuer(JcaX509CertificateHolder(caCert), digCalcProv)
                            && resp.responses.first().certID.serialNumber.equals(eeCert.serialNumber)
                            && resp.responses.first().certStatus == null
                }
            }
            return false
//            throw IllegalStateException("OCSP Request Failed.")
        }
    }

    fun ocsp() {
        val caCert = X509Utilities.loadCertificateFromPEMFile(Common.inputParameter.ocsp_caCert!!)
        val cert = X509Utilities.loadCertificateFromPEMFile(Common.inputParameter.ocsp_cert!!)
        val req = makeOCSPRequest(caCert, cert)

        val ocspResp = sendOCSPReq(req, Common.inputParameter.ocsp_url)
        val isGood = isGoodCertificate(ocspResp, caCert, cert)
        println("is cert good: $isGood")

        println("status: ${ocspResp.status}")

        val resp: BasicOCSPResp = ocspResp.responseObject as BasicOCSPResp
        println("isSignatureValid: ${resp.isSignatureValid(JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider()).build(caCert.publicKey))}")
        val digCalcProv: DigestCalculatorProvider = JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
        println("matchesIssuer: ${resp.responses.first().certID.matchesIssuer(JcaX509CertificateHolder(caCert), digCalcProv)}")
        println("serialNumber matches: ${resp.responses.first().certID.serialNumber.equals(cert.serialNumber)}")
        println("certStatus: ${resp.responses.first().certStatus}")
    }
}




