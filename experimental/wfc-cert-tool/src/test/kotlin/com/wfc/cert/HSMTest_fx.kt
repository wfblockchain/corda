package com.wfc.cert

import com.wfc.cert.Common.Companion.saveCertInJKSKeyStoreFile
import net.corda.core.crypto.internal.AliasPrivateKey
import net.corda.core.crypto.internal.cordaBouncyCastleProvider
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.CertRole
import net.corda.nodeapi.internal.crypto.save
import org.junit.Before
import org.junit.Test
import java.security.KeyStore
import java.security.Provider
import java.nio.file.Path
import java.nio.file.Paths
import java.security.Signature
import kotlin.test.assertTrue

/**
 * This test assumes an HSM is set up for connection.
 * If there is no HSM setup, need to comment out the whole class for safety.
 */
class HSMTest_fx {
    val configFileName = "C:/Users/szhang0/z/bps/Blockchain/Corda/utimaco/CryptoServer/Simulator/sun_pkcs11.cfg"
//    val pin = "123456"
    val pin = "safest"
    val keypass = "trustpass"
    val storepass = "trustpass"
    val x500Name = CordaX500Name.parse("CN=Sean Z,OU=SeanOU, O=SeanO, L=Concord, C=US")
    val aliasForHSM = Common.identityAlias // "identity-private-key" // "cordaclientca"
    val aliasForJKS = "csr"
    val zone = "DEV"
    val ecCurve = Common.eccCurve //"secp256r1"
    val outputFolder: Path = Paths.get("C:/Users/szhang0/z/bps/Blockchain/Corda/utimaco/CryptoServer/Simulator/tests")
    val jksProvider = cordaBouncyCastleProvider
    lateinit var keyStore: KeyStore
    /**
     * This is the HSM provider only. For JKS, we use jksProvider.
     */
    lateinit var provider: Provider
    lateinit var dummyCSRBuilder: CSRBuilder

    @Before
    fun setup() {
        val (ks, prov) = HSM.loginHSM(pin, "SunPKCS11", configFileName)
        keyStore = ks
        provider = prov
        dummyCSRBuilder = CSRBuilder(keyStoreType = "JKS", provider = provider, legalName = x500Name)
    }

    @Test
    fun `CSRBuilder in PKCS11, and then save privatekey and cert in HSM, and cert in jks file and csr in p10 file`() {
        val builder = CSRBuilder("PKCS11", provider, "EC", ecCurve, 0, Common.eccScheme, x500Name, CertRole.LEGAL_IDENTITY, zone).apply {
            initialize(pin)
        }
        val builderData = builder.build()
        // Save private key and cert in HSM
        builderData.keyStore.deleteEntry(aliasForHSM)
        builderData.keyStore.setKeyEntry(aliasForHSM, builderData.keyPair.private, null, arrayOf(builderData.cert))
        // Save AliasPrivateKey and cert in JKS
        saveCertInJKSKeyStoreFile(builderData.cert, x500Name, outputFolder, AliasPrivateKey(aliasForHSM), aliasForJKS, keypass, storepass, "identity")
        // Save csr in p10 file
        saveCSRFile(builderData.csr, x500Name, outputFolder, "identity")
    }

    @Test
    fun `CSRBuilder in JKS, and then save private key and cert in jks file and csr in p10 file`() {
        val keystoreFile = Common.outputFile(outputFolder, "${Common.nameFromLegalName(x500Name).toLowerCase()}_tls.jks")
        val builder = CSRBuilder("JKS", jksProvider, "EC", ecCurve, 0, Common.eccScheme, x500Name, CertRole.TLS, zone).apply {
            initialize(keystoreFile, storepass)
        }
        val builderData = builder.build()
        // Save private key and cert in the same keystore file using the same keyStore
        builderData.keyStore.setKeyEntry(aliasForJKS, builderData.keyPair.private, storepass.toCharArray(), arrayOf(builderData.cert))
        builderData.keyStore.save(keystoreFile, storepass)
        // Save csr in p10 file
        saveCSRFile(builderData.csr, x500Name, outputFolder, "tls")
    }

    @Test
    fun `Generate EC KeyPair`() {
        val kp = dummyCSRBuilder.generateKeypair("EC", ecCurve, 0, provider)
        println("generateKeypair - genKeyPair() gets pubKey = ${kp.public}, privKey = ${kp.private} - done")
    }

    @Test
    fun `Generate RSA KeyPair`() {
        val kp = dummyCSRBuilder.generateKeypair("RSA", "", 2048, provider)
        println("generateKeypair - genKeyPair() gets pubKey = ${kp.public}, privKey = ${kp.private} - done")
    }

    /**
     * This test is being replaced by
     * `CSRBuilder in PKCS11, and then save privatekey and cert in HSM, and cert in jks file and csr in p10 file`
     */
//    @Test
    fun `Save KeyPair and Cert in HSM, Create CSR, save Cert and AliasPrivateKey to jks file, same CSR file`() {
        val keyPair = dummyCSRBuilder.generateKeypair("EC", ecCurve, 0, provider)
        println("generateKeypair - genKeyPair() gets pubKey = ${keyPair.public}, privKey = ${keyPair.private} - done")

        val cert = dummyCSRBuilder.generateCert(x500Name, keyPair, provider, Common.eccScheme)
        println("generateCert gets cert SN = ${cert.serialNumber} - done")

        // Delete previous entry before saving
        keyStore.deleteEntry(aliasForHSM)

        keyStore.setKeyEntry(aliasForHSM, keyPair.private, null, arrayOf(cert))

        /**
         * Test saving AliasPrivateKey instead of an actual private key
         */
        val aliasPrivateKey = AliasPrivateKey("identity-private-key")
        saveCertInJKSKeyStoreFile(cert, x500Name, outputFolder, aliasPrivateKey, "csr", keypass, storepass, "identity")

        val csr = dummyCSRBuilder.generateCSR(x500Name, keyPair, provider, Common.eccScheme)
        println("generateCSR gets CSR attributes = ${csr.attributes} - done")
        saveCSRFile(csr, x500Name, outputFolder, "identity")
    }

    @Test
    fun `Sign some data`() {
        val keyPair = dummyCSRBuilder.generateKeypair("EC", ecCurve, 0, provider)
        println("generateKeypair - genKeyPair() gets pubKey = ${keyPair.public}, privKey = ${keyPair.private} - done")

        val signatureScheme = Common.eccScheme
        // sign some data
        val sig = Signature.getInstance(signatureScheme.algorithmName, provider)
        sig.initSign(keyPair.private)
        val data = "test".toByteArray()
        sig.update(data)
        val s = sig.sign()
        println("Signed with hardware key.")

        // verify the signature
        sig.initVerify(keyPair.public)
        sig.update(data)
        assertTrue { sig.verify(s) }
        println("Verified with hardware key.")
    }

    /**
     * This runs fine by itself.
     * But if run with the Cert test together, get error about private key not in the right form.
     */
//    @Test
    fun `Create CSR with Keypair in HSM`() {
        val keyPair = dummyCSRBuilder.generateKeypair("EC", "secp256r1", 0, provider)
        println("generateKeypair - genKeyPair() gets pubKey = ${keyPair.public}, privKey = ${keyPair.private} - done")

        val csr = dummyCSRBuilder.generateCSR(x500Name, keyPair, provider, Common.eccScheme)
        println("generateCSR gets CSR attributes = ${csr.attributes} - done")
    }
}