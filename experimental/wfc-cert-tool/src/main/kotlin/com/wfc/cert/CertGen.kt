package com.wfc.cert

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import com.typesafe.config.ConfigParseOptions
import com.wfc.cert.Common.Companion.csrDefFromConfig
import com.wfc.cert.Common.Companion.dummyNodeAlias
import com.wfc.cert.Common.Companion.eccScheme
import com.wfc.cert.Common.Companion.generateCSRAndCert
import com.wfc.cert.Common.Companion.identityAlias
import com.wfc.cert.Common.Companion.inputParameter
import com.wfc.cert.Common.Companion.jksFileNameFromLegalName
import com.wfc.cert.Common.Companion.nameFromLegalName
import com.wfc.cert.Common.Companion.nameFromLegalNameInLowerCase
import com.wfc.cert.Common.Companion.networkmapAlias
import com.wfc.cert.Common.Companion.networkparametersAlias
import com.wfc.cert.Common.Companion.outputFile
import com.wfc.cert.Common.Companion.rootAlias
import com.wfc.cert.Common.Companion.sslAliase
import net.corda.cliutils.CordaCliWrapper
import net.corda.cliutils.start
import net.corda.core.CordaOID
import net.corda.core.crypto.Crypto
import net.corda.core.crypto.random63BitValue
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.CertRole
import net.corda.core.internal.div
import net.corda.core.internal.writer
import net.corda.nodeapi.internal.crypto.*
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
import picocli.CommandLine.Option
import java.lang.IllegalArgumentException
import java.math.BigInteger
import java.nio.file.Path
import java.security.KeyPair
import java.security.SignatureException
import java.security.cert.X509Certificate
import java.util.*

/**
 * WFC Internal Corda Network Certificate Utility Tool
 * Generate the complete tree of certificates for A' or A, based on a config. This is for non-PROD use.
 * Create CSRs for the nodes and/or networkmap and/or networkparameters and keep the keys in JKS
 * Example confs are in resources/cert_defs.conf and csr_defs.conf
 * Two commands: cert and csr, only one can execute at a time
 * Each command must have its own --config; --output is optional - if not provided, output will be in
 * either the certs or csrs subfolder of the folder where config file is.
 */
fun main(args: Array<String>) {
    CertGen().start(args)
}

class Common {
    companion object {
        const val rootAlias = "cordarootca"
        const val issuingCAAlias = "cordaissuingca"
        const val dummyNodeAlias = "cordaclientca"
        const val identityAlias = "identity-private-key"
        const val sslAliase = "cordaclienttls"
        const val networkmapAlias = "networkmap"
        const val networkparametersAlias = "networkparameters"
        val rsaScheme = Crypto.RSA_SHA256
        val eccScheme = Crypto.ECDSA_SECP256R1_SHA256

        val inputParameter = InputParameter()

        fun nameFromLegalName(legalName: CordaX500Name) = ("${legalName.commonName ?: legalName.organisationUnit ?: legalName.organisation}")//.toLowerCase()
        fun nameFromLegalNameInLowerCase(legalName: CordaX500Name) = "${nameFromLegalName(legalName)}".toLowerCase()
        fun jksFileNameFromLegalName(legalName: CordaX500Name) = nameFromLegalNameInLowerCase(legalName) + ".jks"
//        fun outputFile(name: String) = outputFolder!! / name
        fun outputFile(parent: Path, name: String) = parent / name

        fun nodeParentOutputFolder(outputFolder: Path) = outputFolder / "nodes"
        fun notaryParentOutputFolder(outputFolder: Path) = outputFolder / "notary"

        fun csrDefFromConfig(file: Path) : CertGen.CSRDef {
            val parseOptions = ConfigParseOptions.defaults().setAllowMissing(true)
            val config = ConfigFactory.parseFile(file.toFile(), parseOptions).resolve()
            return passCSRConfig(config)
        }

        private fun passCSRConfig(config: Config) : CertGen.CSRDef {
            val zone = if (config.hasPath("zone")) config.getString("zone") else "DEV"
            val nodes = if (config.hasPath("nodes")) config.getStringList("nodes").map { CordaX500Name.parse(it) } else emptyList()
            return CertGen.CSRDef(
                    zone = zone,
                    nodes = nodes,
                    networkMap = if (config.hasPath("networkMap")) CordaX500Name.parse(config.getString("networkMap")) else null,
                    networkParameters = if (config.hasPath("networkParameters")) CordaX500Name.parse(config.getString("networkParameters")) else null,
                    alias = config.getString("alias"),
                    storepass = config.getString("storepass"),
                    keypass = config.getString("keypass")
            )
        }

        fun generateCSRAndCert(legalName: CordaX500Name, certRole: CertRole, zone: String): Triple<KeyPair, PKCS10CertificationRequest, X509Certificate> {
            val signatureScheme = eccScheme
            val keyPair = Crypto.generateKeyPair(signatureScheme)
            val signer = ContentSignerBuilder.build(signatureScheme, keyPair.private, Crypto.findProvider(signatureScheme.providerName))
            val extGen = ExtensionsGenerator()
            /**
             * Basic Constraint
             */
            val basicConstraints = BasicConstraints(false)
            extGen.addExtension(Extension.basicConstraints, true, basicConstraints)
            /**
             * Key Usage
             * per Rich Stec, he will set KU himself.
             */
//        val keyUsage = KeyUsage (KeyUsage.digitalSignature or KeyUsage.keyCertSign)
//        extGen.addExtension(Extension.keyUsage, true, keyUsage)
            /**
             * Extended Key Usage
             * per Rich Stec, he will set EKU himself
             */
//        val extendedKeyUsage = ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_codeSigning, KeyPurposeId.id_kp_clientAuth))
//        extGen.addExtension(Extension.extendedKeyUsage, true, extendedKeyUsage)

            /**
             * per Rich Stec, he will set Email and certRole
             * Add attribute Corda-Zone
             */
            val csr = JcaPKCS10CertificationRequestBuilder(legalName.x500Principal, keyPair.public)
//                .addAttribute(BCStyle.E, DERUTF8String("test@mysite.com"))
//                .addAttribute(ASN1ObjectIdentifier(CordaOID.X509_EXTENSION_CORDA_ROLE), certRole)
                    .addAttribute(ASN1ObjectIdentifier("2.16.840.1.114171.4.1.2.7"), DERUTF8String(zone))
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
            calendar.set(2019, Calendar.JANUARY, 1, 0, 0, 0)
            val notBefore: Date = calendar.time
            calendar.set(2028, Calendar.DECEMBER, 31, 23, 59, 59)
            val notAfter: Date = calendar.time

            val builder = JcaX509v3CertificateBuilder(legalName.x500Principal, serial, notBefore, notAfter, legalName.x500Principal, keyPair.public)
                    .addExtension(ASN1ObjectIdentifier(CordaOID.X509_EXTENSION_CORDA_ROLE), false, certRole)
                    .addExtension(Extension.basicConstraints, true, basicConstraints)
//                .addExtension(Extension.keyUsage, false, keyUsage)
//                .addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage)
            val cert = builder.build(signer).run {
                require(isValidOn(Date()))
                require(isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))){"Invalid signature"}
                toJca()
            }
            return Triple(keyPair, csr, cert)
        }
    }
}

data class InputParameter (
        var configFile: Path? = null,
        var csrFolder: Path? = null,
        var cerFolder: Path? = null,
        var base_directory: Path? = null,
        var outputFolder: Path? = null,
        var keystorepass: String = "cordacadevpass",
        var truststorepass: String = "trustpass",
        var networkkeystorepass: String = "trustpass"
)

class CertGen : CordaCliWrapper("certgen", "Generate certificates or CSRs") {
    @Option(names = ["cert"], description = ["Command to generate certs"])
    private var cert: Boolean = false

    @Option(names = ["csr"], description = ["Command to generate CSRs"])
    private var csr: Boolean = false

    @Option(names = ["csrOnNode"], description = ["Command to generate CSRs directly on the node"])
    private var csrOnNode: Boolean = false

    @Option(names = ["truststore"], description = ["Command to generate truststore.jks from cer"])
    private var truststore: Boolean = false
    @Option(names = ["jks"], description = ["Command to generate jks files for networkmap, networkparameters, node, ssl"])
    private var jks: Boolean = false
    @Option(names = ["jksOnNode"], description = ["Command to generate jks files for node, ssl directly on the node"])
    private var jksOnNode: Boolean = false
//    @Option(names = ["networkmap"], description = ["Command to generate networkmap.jks"])
//    private var networkmap: Boolean = false
//    @Option(names = ["networkparameters"], description = ["Command to generate networkparameters.jks"])
//    private var networkparameters: Boolean = false
//    @Option(names = ["node"], description = ["Command to generate nodekeystore.jks"])
//    private var node: Boolean = false
//    @Option(names = ["ssl"], description = ["Command to generate sslkeystore.jks"])
//    private var ssl: Boolean = false

    /**
     * It is required for cert, csr, csrOnNode, jks, jksOnNode.
     * csr and jks share the same conf.
     * That means after csrs have been created, we should keep the corresponding conf and use
     * it for jks.
     * For csrOnNode and jksOnNode, we also use node.conf, which is in base-directory.
     */
    @Option(names = ["--config"], paramLabel = "file", description = ["Path to the conf file."])
    private var configFile: Path? = null

    /**
     * For jks, this folder has the private keys genereated when csr was called.
     * It is the --output folder for the csr command.
     * It is required for jks.
     * For jksOnNode, it uses base-directory/csr
     */
    @Option(names = ["--csr"], paramLabel = "file", description = ["Path to csr folder."])
    private var csrFolder: Path? = null

    /**
     * This is the folder where the issued .cer files are. We assume that the folder itself
     * holds rca.cer, ica1.cer, ica2.cer and the subfolder ./cer holds the other .cer files.
     * For jksOnNode, it uses base-directory/cer and base-directory/cer/cer.
     */
    @Option(names = ["--cer"], paramLabel = "file", description = ["Path to cer folder."])
    private var cerFolder: Path? = null

    /**
     * This is required for csrOnNode and jksOnNode.
     */
    @Option(names = ["--base-directory"], paramLabel = "file", description = ["Path to the Corda node folder."])
    private var base_directory: Path? = null

    /**
     *
     */
    @Option(names = ["--output"], paramLabel = "file", description = ["Path to output folder."])
    private var outputFolder: Path? = null

    @Option(names = ["--keystore-pass"], paramLabel = "password", description = ["Password for the node and ssl keystores."])
    private var keystorepass: String = "cordacadevpass"

    @Option(names = ["--truststore-pass"], paramLabel = "password", description = ["Password for the truststore."])
    private var truststorepass: String = "trustpass"

    @Option(names = ["--network-keystore-pass"], paramLabel = "password", description = ["Password for the networkMap and networkparameters keystores."])
    private var networkkeystorepass: String = "trustpass"

    private fun Boolean.toInt() = if (this) 1 else 0

    override fun runProgram(): Int {
        require(cert.toInt() + csr.toInt() + csrOnNode.toInt() + truststore.toInt() + jks.toInt() + jksOnNode.toInt() == 1) { "One and only one must be specified" }
//        require(cert.toInt() + csr.toInt() + truststore.toInt() + networkmap.toInt() + networkparameters.toInt() + node.toInt() + ssl.toInt() == 1) { "One and only one must be specified" }
//        require(cert.xor(csr)) { "One and only one of commands cert and csr must be specified" }
        require(((cert || csr || jksOnNode || jks || jksOnNode) && configFile != null) || !(cert || csr || jksOnNode || jks || jksOnNode)) { "The --config parameter must be specified for cert, csr, csrOnNode, jks and jksOnNode" }
        require((jks && csrFolder != null) || !jks) { "jks requires csr folder" }
        require(((truststore || jks) && cerFolder != null) || !(truststore || jks)) { "truststore and jks require cer folder" }
        require(((csrOnNode || jksOnNode) && base_directory != null) || !(csrOnNode || jksOnNode)) { "csrOnNode and jksOnNode require base-directory folder" }

        if (outputFolder == null) outputFolder = if (cert) (configFile!!.parent) / "certs" else if (csr) (configFile!!.parent) / "csrs" else if (truststore || jks) cerFolder else null
        if (csrOnNode) outputFolder = base_directory!! / "csr"
        if (jksOnNode) outputFolder = base_directory!! / "certificates"
        if (jksOnNode) csrFolder = base_directory!! / "csr"
        if (jksOnNode) cerFolder = base_directory!! / "cer"

        /**
         * We use also {} instead apply {} to distinguish between variables in it and this.
         */
        inputParameter.also {
            it.configFile = this.configFile
            it.csrFolder = this.csrFolder
            it.cerFolder = this.cerFolder
            it.base_directory = this.base_directory
            it.outputFolder = this.outputFolder
            it.keystorepass = this.keystorepass
            it.truststorepass = this.truststorepass
            it.networkkeystorepass = this.networkkeystorepass
        }

        if (cert) {
            generateCerts()
        } else if (csr) {
            generateCSRs()
        } else if (csrOnNode) {
            generateCSRsOnNode()
        } else if (truststore) {
            createTrustStore()
        } else if (jks) {
            createJKSs()
        } else if (jksOnNode) {
            createJKSsOnNode()
        }
        /**
         * Note: This is for double protection since we have already done the require checking earlier.
         */
        else {
            throw IllegalArgumentException("Missing or known command!")
        }

        return 0
    }

    private fun createTrustStore() {
        val cerFile = outputFile(cerFolder!!, "rca.cer")
        val jksFile = outputFile(outputFolder!!,"truststore.jks")
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)
        val keyStore = loadOrCreateKeyStore(jksFile, truststorepass)
        keyStore.setCertificateEntry(rootAlias, cert)
        keyStore.save(jksFile, truststorepass)
    }


    data class CertDef (
            val zone: String = "DEV",
            val root: NameAndPass,
            val issuingCAs: List<IssuingCA>,
            val nodes: Nodes,
            val notary: Notary,
            val networkMap: NameAndPass,
            val networkParameters: NameAndPass

    )
    data class NameAndPass (
            val legalName: CordaX500Name,
            val storepass: String,
            val keypass: String
    )
    data class IssuingCA (
            val nameAndPass: NameAndPass,
            val doormanRole: Boolean
    )
    data class Nodes (
            val legalNames: List<CordaX500Name>,
            val storepass: String,
            val keypass: String
    )
    data class Notary (
            val service_legalName: CordaX500Name,
            val worker_legalNames: List<CordaX500Name>,
            val storepass: String,
            val keypass: String
    )

    data class CSRDef (
       val zone: String = "DEV",
       val nodes: List<CordaX500Name>?,
       val networkMap: CordaX500Name?,
       val networkParameters: CordaX500Name?,
       val alias: String,
       val storepass: String,
       val keypass: String
    )

    /**
     * Move the following to Common.Companion
     */
/*
    private fun nameFromLegalName(legalName: CordaX500Name) = ("${legalName.commonName ?: legalName.organisationUnit ?: legalName.organisation}")//.toLowerCase()
    private fun nameFromLegalNameInLowerCase(legalName: CordaX500Name) = "${nameFromLegalName(legalName)}".toLowerCase()
    private fun jksFileNameFromLegalName(legalName: CordaX500Name) = nameFromLegalNameInLowerCase(legalName) + ".jks"
//    private fun jksFileNameFromLegalName(legalName: CordaX500Name) = ("${nameFromLegalName(legalName)}.jks").toLowerCase()
    private fun outputFile(name: String) = outputFolder!! / name
    private fun outputFile(parent: Path, name: String) = parent / name
//    private fun nodeParentOutputFolder() = outputFolder!! / "nodes"
//    private fun notaryParentOutputFolder() = outputFolder!! / "notary"
//
*/

}