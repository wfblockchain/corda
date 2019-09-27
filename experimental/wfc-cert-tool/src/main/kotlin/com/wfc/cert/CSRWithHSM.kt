package com.wfc.cert

import com.wfc.cert.Common.Companion.HSM_PROVIDER
import fx.security.pkcs11.SunPKCS11
import net.corda.core.crypto.Crypto
import net.corda.core.crypto.SignatureScheme
import net.corda.core.crypto.random63BitValue
import net.corda.core.identity.CordaX500Name
import net.corda.nodeapi.internal.crypto.ContentSignerBuilder
import net.corda.nodeapi.internal.crypto.isSignatureValid
import net.corda.nodeapi.internal.crypto.toJca
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.time.Year
import java.util.*

//fun generateCSRsOnNodeWithHSM() {
//    Security.addProvider(SunPKCS11())
//}

/**
 * This is a sample code for generating a keypay.
 * Q: Where is the HSM connection done?
 * A: FutureX has a privare flag on the key. If true, then authentication is required.
 *      We will use private true.
 *      KeyStore.load(...) is the authentication piece.
 * Q: What does C_Login invocation do?
 *      hSession, CKU_USER, (CK_BYTE *)"123456", 6);
 *      Do we have the equivalent in Java?
 * A: KeyStore.load(...)
 * Q: Where is the HSM authentication done?
 * A: KeyStore.load(...)
 * Q: Which slot is keypair stored in?
 * Q: How about label which is the unique identifier by the outside to link the private key inside HSM?
 * A: Looks like if we don't explicitly specify it, it will be created by HSM automatically.
 */
private fun generateKeypairOnHSM(sigScheme: SignatureScheme, loginStr: String): KeyPair {
    Security.addProvider(SunPKCS11())
//    val loginStr = "safe"
    val ks: KeyStore = KeyStore.getInstance("PKSC11", HSM_PROVIDER)
    ks.load(null, loginStr.toCharArray())
    val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(sigScheme.algorithmName, HSM_PROVIDER)
    /**
     * Do we need to use P11KeyParams for key pair generation?
     * We only have examples for symmetric keys.
     * One good (bad) aspect of it is to set label
     */
    /*
    val kparam = P11KeyParams()
    kparam.label = "abd"
    kpg.initialize(kparam)
    */
    kpg.initialize(sigScheme.algSpec)

    val kp: KeyPair = kpg.genKeyPair()  // only reference to private key - label
    return kp  // only reference to private key - label
}

/**
 *
 */
private fun generateCSRAndCertOnHSM(legalName: CordaX500Name): Triple<KeyPair, PKCS10CertificationRequest, X509Certificate> {
    val signatureScheme = Common.eccScheme
    val loginStr: String = Common.inputParameter.hsm_login!!
    val keyPair = generateKeypairOnHSM(signatureScheme, loginStr)
    val signer = ContentSignerBuilder.build(signatureScheme, keyPair.private, SunPKCS11())
    val extGen = ExtensionsGenerator()
    /**
     * Basic Constraint
     */
    val basicConstraints = BasicConstraints(false)
    extGen.addExtension(Extension.basicConstraints, true, basicConstraints)

    val csr = JcaPKCS10CertificationRequestBuilder(legalName.x500Principal, keyPair.public)
            .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate())
            .build(signer).apply {
                if (!isSignatureValid()) {
                    throw SignatureException("The certificate signing request signature validation failed.")
                }
            }

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
            .addExtension(Extension.basicConstraints, true, basicConstraints)
    val cert = builder.build(signer).run {
        require(isValidOn(Date()))
        require(isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))){"Invalid signature"}
        toJca()
    }
    return Triple(keyPair, csr, cert)
}


/**
 * Find and return keys stored on HSM.
 * By type.
 * How do we get a key in a specific slot?
 * Note: Key should not leave HSM. So this is just a theoretical exercise.
 */
private fun getKeyStoreFromFX(loginStr: String): KeyStore {
    val ks: KeyStore = KeyStore.getInstance("PKCS11", "FutureX")
    /**
     * This will authenticate to the HSM.
     */
    ks.load(null, loginStr.toCharArray())
//    ks.getKey("alias", loginStr.toCharArray())
    return ks
}
