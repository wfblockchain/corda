package com.wfc.cert

import net.corda.core.CordaOID
import net.corda.core.crypto.SignatureScheme
import net.corda.core.crypto.random63BitValue
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.CertRole
import net.corda.core.internal.writer
import net.corda.nodeapi.internal.crypto.ContentSignerBuilder
import net.corda.nodeapi.internal.crypto.isSignatureValid
import net.corda.nodeapi.internal.crypto.loadOrCreateKeyStore
import net.corda.nodeapi.internal.crypto.toJca
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERUTF8String
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemObject
import java.math.BigInteger
import java.nio.file.Path
import java.security.*
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Year
import java.util.*

/**
 * We pass in provider. we should support both SunPKCS11 and cordaBouncyCastleProvider.
 * keyStoreType: either PKCS11 or JKS
 * We want to build keyStore, keyPair, cert and csr so the caller can decide how to persist:
 *  e.g., csr to file, keypair and cert to HSM and/or JKS file
 *  TODO:
 *      1. How can validate keyStoreType and provider against each other?
 *          We have tested ("PKCS11", SunPKCS11()), ("JKS", cordaBouncyCastleProvider) .
 *      2. How can we validate keyAlg, keyCurve and sigScheme against each other?
 *          We have tested ("EC", "secp256r1", Crypto.ECDSA_SECP256R1_SHA256) and
 *          ("RSA", no curve, Crypto.RSA_SHA256)
 */
open class CSRBuilder(
        open val keyStoreType: String,
        open val provider: Provider,
        private val keyAlg: String = "EC", // EC or RSA
        val keyCurve: String = "secp256r1",
        val keySize: Int = 0,
        val sigScheme: SignatureScheme = Common.eccScheme,
        val legalName: CordaX500Name,
        val certRole: CertRole = CertRole.LEGAL_IDENTITY,
        val zone: String = "DEV"
        ) {
    private lateinit var keyStore: KeyStore
    fun initialize(pin: String) {
        this.keyStore = KeyStore.getInstance(keyStoreType, provider)
        require(keyStoreType == "PKCS11") { "This initialize function only applies to PKCS11." }
        this.keyStore.load(null, pin.toCharArray())
    }

    fun initialize(jksFile: Path, storepass: String) {
        require(keyStoreType == "JKS") { "This initialize function only applies to JKS." }
        this.keyStore = loadOrCreateKeyStore(jksFile, storepass)
    }

    fun build(): CSRBuilderData {
//    fun build(): Quadruple<KeyStore, KeyPair, X509Certificate, PKCS10CertificationRequest> {
        val keyPair = generateKeypair(keyAlg, keyCurve, keySize, provider)
        val cert = generateCert(legalName, keyPair, provider, sigScheme)
        val csr = generateCSR(legalName, keyPair, provider, sigScheme)
        return CSRBuilderData(keyStore = keyStore, keyPair = keyPair, cert= cert, csr = csr)
//        return Quadruple(keyStore, keyPair, cert, csr)
    }

    /**
     * We make it a self-contained function with complete parameters so that
     * it can be tested relatively easily by itself.
     */
    fun generateKeypair(algorithm: String, curve: String, keySize: Int, provider: Provider): KeyPair {
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider)
        if (algorithm == "EC") {
            val kpgparams = ECGenParameterSpec(curve)
            kpg.initialize(kpgparams)
        }
        else {
            kpg.initialize(keySize)
        }

        val kp: KeyPair = kpg.genKeyPair()  // only reference to private key - label
        return kp  // only reference to private key - label
    }

    /**
     * We make it a self-contained function with complete parameters so that
     * it can be tested relatively easily by itself.
     */
    fun generateCert(legalName: CordaX500Name, keyPair: KeyPair, provider: Provider, signatureScheme: SignatureScheme, certRole: CertRole = CertRole.LEGAL_IDENTITY): X509Certificate {
//        val signatureScheme = Common.eccScheme
        val signer = ContentSignerBuilder.build(signatureScheme, keyPair.private, provider)
        /**
         * Basic Constraint
         */
        val basicConstraints = BasicConstraints(false)
        val serial = BigInteger.valueOf(random63BitValue())
        /**
         * Validity Window
         */
        val calendar = GregorianCalendar()
        val year = Year.now().value
        calendar.set(year, Calendar.JANUARY, 1, 0, 0, 0)
        val notBefore: Date = calendar.time
        calendar.set(year + 9, Calendar.DECEMBER, 31, 23, 59, 59)
        val notAfter: Date = calendar.time

        val builder = JcaX509v3CertificateBuilder(legalName.x500Principal, serial, notBefore, notAfter, legalName.x500Principal, keyPair.public)
                .addExtension(ASN1ObjectIdentifier(CordaOID.X509_EXTENSION_CORDA_ROLE), false, certRole)
                .addExtension(Extension.basicConstraints, true, basicConstraints)
        val cert = builder.build(signer).run {
            require(isValidOn(Date()))
            require(isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))){"Invalid signature"}
            toJca()
        }
        cert.checkValidity(Date())
        cert.verify(keyPair.public)
        return cert
    }

    /**
     * We make it a self-contained function with complete parameters so that
     * it can be tested relatively easily by itself.
     */
    fun generateCSR(legalName: CordaX500Name, keyPair: KeyPair, provider: Provider, signatureScheme: SignatureScheme, zone: String = "DEV"): PKCS10CertificationRequest {
//        val signatureScheme = Common.eccScheme
        val signer = ContentSignerBuilder.build(signatureScheme, keyPair.private, provider)
        val extGen = ExtensionsGenerator()
        /**
         * Basic Constraint
         */
        val basicConstraints = BasicConstraints(false)
        extGen.addExtension(Extension.basicConstraints, true, basicConstraints)

        val csr = JcaPKCS10CertificationRequestBuilder(legalName.x500Principal, keyPair.public)
                .addAttribute(ASN1ObjectIdentifier("2.16.840.1.114171.4.1.2.7"), DERUTF8String(zone))
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate())
                .build(signer).apply {
                    if (!isSignatureValid()) {
                        throw SignatureException("The certificate signing request signature validation failed.")
                    }
                }
        return csr
    }

}

fun saveCSRFile(csr: PKCS10CertificationRequest, legalName: CordaX500Name, outputFolder: Path, fileNameSuffix: String? = null) {
    val csrFile = Common.outputFile(outputFolder, "${Common.nameFromLegalName(legalName).toLowerCase()}${if (fileNameSuffix != null) "_" + fileNameSuffix else ""}.p10")
//    val csrFile = Common.outputFile(outputFolder, "${Common.nameFromLegalName(legalName).toLowerCase()}_$fileNameSuffix.p10")
    JcaPEMWriter(csrFile.writer()).use {
        it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded))
    }
}

data class Quadruple<T1, T2, T3, T4>(val v1: T1, val v2: T2, val v3: T3, val v4: T4)
data class CSRBuilderData(val keyStore: KeyStore, val keyPair: KeyPair, val cert: X509Certificate, val csr: PKCS10CertificationRequest)
