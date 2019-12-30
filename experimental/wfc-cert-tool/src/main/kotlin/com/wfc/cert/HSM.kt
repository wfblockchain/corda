package com.wfc.cert

import net.corda.core.crypto.internal.cordaBouncyCastleProvider
import sun.security.pkcs11.SunPKCS11
import fx.security.pkcs11.SunPKCS11 as FXSunPKCS11
import java.security.KeyStore
import java.security.Provider
import java.security.Security

class HSM {
    companion object {
        fun loginHSM(pin: String, providerName: String = "Futurex", configFileName: String? = null): Pair<KeyStore, Provider> {
            val provider = if(providerName == "Futurex") FXSunPKCS11() else SunPKCS11(configFileName)
            Security.addProvider(provider)
//            val ks: KeyStore = KeyStore.getInstance("PKCS11", provider)
            val ks: KeyStore = KeyStore.getInstance("PKCS11", providerName)
            // Authenticate to HSM
            ks.load(null, pin.toCharArray())
            return Pair(ks, provider)
        }

        /**
         * Here not hasHSM, we default to cordaBouncyCastleProvider
         */
        fun getProvider(hasHSM: Boolean, providerName: String? = "Futurex", configFileName: String?): Provider {
            return if (hasHSM)
                    if (providerName == "Futurex") FXSunPKCS11() else SunPKCS11(configFileName)
                else cordaBouncyCastleProvider
        }
    }
}
/*
/**
 *
 */
private fun generateCSRAndCertOnHSM(legalName: CordaX500Name): Triple<KeyPair, PKCS10CertificationRequest, X509Certificate> {
    val signatureScheme = Common.eccScheme
    val loginStr: String = Common.inputParameter.hsm_login!!
    val keyPair = generateKeypair(signatureScheme, loginStr)
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
*/