package com.wfc.cert

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import com.typesafe.config.ConfigParseOptions
import net.corda.cliutils.*
import net.corda.core.CordaOID
import net.corda.core.crypto.Crypto
import net.corda.core.crypto.random63BitValue
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.CertRole
import net.corda.core.internal.div
import net.corda.core.internal.toX500Name
import net.corda.core.internal.writer
import net.corda.nodeapi.internal.crypto.*
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.bc.BcX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemObject
import picocli.CommandLine.*
import java.lang.IllegalArgumentException
import java.math.BigInteger
import java.nio.file.Path
import java.security.KeyPair
import java.security.SignatureException
import java.security.cert.X509Certificate
import java.util.*
import javax.security.auth.x500.X500Principal

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

        if (cert) {
            generateCerts(configFile!!)
        } else if (csr) {
            generateCSRs(configFile!!)
        } else if (csrOnNode) {
            generateCSRsOnNode(configFile!!)
        } else if (truststore) {
            createTrustStore()
        } else if (jks) {
            createJKSs(configFile!!)
        } else if (jksOnNode) {
            createJKSsOnNode(configFile!!)
        }

        return 0
    }

    private val rootAlias = "cordarootca"
    private val issuingCAAlias = "cordaissuingca"
    private val dummyNodeAlias = "cordaclientca"
    private val identityAlias = "identity-private-key"
    private val sslAliase = "cordaclienttls"
    private val networkmapAlias = "networkmap"
    private val networkparametersAlias = "networkparameters"
    private val rsaScheme = Crypto.RSA_SHA256
    private val eccScheme = Crypto.ECDSA_SECP256R1_SHA256

    private fun generateCerts(configFile: Path) {
        val certDef = certDefFromConfig(configFile)
        val (rootFile, trustStoreFile) = createRootAndTrustKeystores(certDef)
        val (issuingCA1File, issuingCA2File) = createIssuingCAKeystores(certDef, rootFile)
        createNodeKeystores(certDef, issuingCA1File, trustStoreFile)
        createNotaryKeystores(certDef, issuingCA1File, trustStoreFile)
        createNetworKeystore(certDef.networkMap, certDef, issuingCA2File, trustStoreFile, CertRole.NETWORK_MAP, networkmapAlias)
        createNetworKeystore(certDef.networkParameters, certDef, issuingCA2File, trustStoreFile, CertRole.NETWORK_PARAMETERS, networkparametersAlias)
    }

    private fun generateCSRs(configFile: Path) {
        val csrDef = csrDefFromConfig(configFile)
        createNodeCSRAndKeystores(csrDef)
        if (csrDef.networkMap != null) createNetworkCSRAndKeystore(csrDef, csrDef.networkMap, CertRole.NETWORK_MAP)
        if (csrDef.networkParameters != null) createNetworkCSRAndKeystore(csrDef, csrDef.networkParameters, CertRole.NETWORK_PARAMETERS)
//        createNetworkCSRAndKeystores(csrDef)
    }

    private fun generateCSRsOnNode(configFile: Path) {
        val csrDef = csrDefFromConfig(configFile)
        val parseOptions = ConfigParseOptions.defaults().setAllowMissing(true)
        val nodeConfig = ConfigFactory.parseFile(outputFile(base_directory!!, "node.conf").toFile(), parseOptions).resolve()
        val legalName = CordaX500Name.parse(nodeConfig.getString("myLegalName"))
        createNodeCSRAndKeystoresForOneNode(csrDef, legalName)
    }

    private fun createTrustStore() {
        val cerFile = outputFile(cerFolder!!, "rca.cer")
        val jksFile = outputFile("truststore.jks")
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)
        val keyStore = loadOrCreateKeyStore(jksFile, truststorepass)
        keyStore.setCertificateEntry(rootAlias, cert)
        keyStore.save(jksFile, truststorepass)
    }

    private fun createJKSs(configFile: Path) {
        val csrDef = csrDefFromConfig(configFile)
        createNodeJKSs(csrDef)
        if (csrDef.networkMap != null) createNetworkJKS(csrDef, networkmapAlias)
        if (csrDef.networkParameters != null) createNetworkJKS(csrDef, networkparametersAlias)
    }

    private fun createJKSsOnNode(configFile: Path) {
        val csrDef = csrDefFromConfig(configFile)
        val parseOptions = ConfigParseOptions.defaults().setAllowMissing(true)
        val nodeConfig = ConfigFactory.parseFile(outputFile(base_directory!!, "node.conf").toFile(), parseOptions).resolve()
        val legalName = CordaX500Name.parse(nodeConfig.getString("myLegalName"))
        createNodeSSLJKS(csrDef, legalName, true)
        createNodeNodeJKS(csrDef, legalName, true)
    }

    private fun createRootAndTrustKeystores(certDef: CertDef): Pair<Path, Path> {
        val rootDef = certDef.root
        val zone = certDef.zone
        val rootcaFile = outputFile(jksFileNameFromLegalName(rootDef.legalName))
        val (keyPair, cert) = generateRootCACert(rootDef, zone)
        val rootCAKeystore = loadOrCreateKeyStore(rootcaFile, rootDef.storepass)
        rootCAKeystore.setKeyEntry(rootAlias, keyPair.private, rootDef.keypass.toCharArray(), arrayOf(cert))
        rootCAKeystore.save(rootcaFile, rootDef.storepass)

        /**
         * truststore
         */
        val rootCert = rootCAKeystore.getX509Certificate(rootAlias)
        val truststoreFile = outputFile("truststore.jks")
        val truststore = loadOrCreateKeyStore(truststoreFile, rootDef.storepass)
        truststore.setCertificateEntry(rootAlias, rootCert)
        truststore.save(truststoreFile, rootDef.storepass)

        return Pair(rootcaFile, truststoreFile)
    }

    private fun generateRootCACert(rootDef: NameAndPass, zone: String): Pair<KeyPair, X509Certificate> {
        val signatureScheme = rsaScheme
        val keyPair = Crypto.generateKeyPair(signatureScheme)
        val subject = rootDef.legalName.x500Principal //  X500Principal(rootDef.legalName)
        val signer = ContentSignerBuilder.build(signatureScheme, keyPair.private, Crypto.findProvider(signatureScheme.providerName))
        val serial = BigInteger.valueOf(random63BitValue())
        val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.public.encoded))
        val subjectKeyIdentifier = BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo)
        val authorityKeyIdentifier = JcaX509ExtensionUtils().createAuthorityKeyIdentifier(keyPair.public)
        /**
         * Validity Window
         */
        val calendar = GregorianCalendar()
        calendar.set(2010, Calendar.JANUARY, 1, 0, 0, 0)
        val notBefore: Date = calendar.time
        calendar.set(2039, Calendar.DECEMBER, 31, 23, 59, 59)
        val notAfter: Date = calendar.time
        /**
         * Basic Constraint
         */
        val basicConstraints = BasicConstraints(true)
        /**
         * Key Usage
         */
        val keyUsage = KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign or KeyUsage.cRLSign)
        /**
         * Extended Key Usage
         */
        val extendedKeyUsage = ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.anyExtendedKeyUsage))

        val builder = JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, keyPair.public)
                .addExtension(ASN1ObjectIdentifier("2.16.840.1.114171.4.1.2.7"), false, DERUTF8String(zone))
                .addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier)
                .addExtension(Extension.basicConstraints, true, basicConstraints)
                .addExtension(Extension.keyUsage, false, keyUsage)
                .addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage)
                .addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier)
        val rootCACert = builder.build(signer).run {
            require(isValidOn(Date()))
            require(isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))){"Invalid signature"}
            toJca()
        }
        return Pair(keyPair, rootCACert)
    }

    private fun createIssuingCAKeystores(certDef: CertDef, rootFile: Path): Pair<Path, Path> {
        val rootDef = certDef.root
        val rootKeystore = loadOrCreateKeyStore(rootFile, rootDef.storepass)
        val rootPrivateKey =  rootKeystore.getSupportedKey(rootAlias, rootDef.keypass)
        val rootCert = rootKeystore.getX509Certificate(rootAlias)
        val rootPublicKey = rootCert.publicKey
        val rootKeyPair = KeyPair(rootPublicKey, rootPrivateKey)
        val rootSubject = rootCert.subjectX500Principal// X500Principal("CN=WFC Corda Root CA, OU=WFC Corda, O=WFC, L=San Francisco, C=US")

        var issuingCA1File: Path? = null
        var issuingCA2File: Path? = null
        if (certDef.issuingCAs.isEmpty()) throw IllegalArgumentException("There must be at least one IssuingCA!")
        certDef.issuingCAs.forEachIndexed { index, issuingCA ->
            val (keyPair, cert) = generateIssuingCACertFromRootCA(issuingCA, rootKeyPair, rootCert)
            val keystoreFile = outputFile(jksFileNameFromLegalName(issuingCA.nameAndPass.legalName))
            val keystore = loadOrCreateKeyStore(keystoreFile, issuingCA.nameAndPass.storepass)
            keystore.setKeyEntry(issuingCAAlias, keyPair.private, issuingCA.nameAndPass.keypass.toCharArray(), arrayOf(cert, rootCert))
            keystore.save(keystoreFile, issuingCA.nameAndPass.storepass)
            when (index) {
                0 -> issuingCA1File = keystoreFile
                1 -> issuingCA2File = keystoreFile
                else -> throw IllegalArgumentException("Too many IssuingCAs: ${index+1}!")
            }
        }

        return Pair(issuingCA1File!!, issuingCA2File ?: issuingCA1File!!)
    }

    private fun generateIssuingCACertFromRootCA(issuingCADef: IssuingCA, rootKeyPair: KeyPair, rootCert: X509Certificate): Pair<KeyPair, X509Certificate> {
        val rootPrincipal = rootCert.subjectX500Principal
        val rootSignatureScheme = Crypto.findSignatureScheme(rootKeyPair.public)
        val signer = ContentSignerBuilder.build(rootSignatureScheme, rootKeyPair.private, Crypto.findProvider(rootSignatureScheme.providerName))

        val signatureScheme = eccScheme
        val keyPair = Crypto.generateKeyPair(signatureScheme)
        val subject = issuingCADef.nameAndPass.legalName.x500Principal
        val serial = BigInteger.valueOf(random63BitValue())
        val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.public.encoded))
        val subjectKeyIdentifier = BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo)
        val authorityKeyIdentifier = JcaX509ExtensionUtils().createAuthorityKeyIdentifier(rootKeyPair.public)
        /**
         * Validity Window
         */
        val calendar = GregorianCalendar()
        calendar.set(2019, Calendar.JANUARY, 1, 0, 0, 0)
        val notBefore: Date = calendar.time
        calendar.set(2028, Calendar.DECEMBER, 31, 23, 59, 59)
        val notAfter: Date = calendar.time
        /**
         * Basic Constraint
         */
        val basicConstraints = BasicConstraints(true)
        /**
         * Key Usage
         */
        val keyUsage = KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign or KeyUsage.cRLSign)
        /**
         * Extended Key Usage
         */
        val extendedKeyUsage = ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.anyExtendedKeyUsage))
        /**
         * CRL Distribution Point
         */
        val distPointName = DistributionPointName(GeneralNames(GeneralName(GeneralName.uniformResourceIdentifier, "http://test.com/crl")))
        val crlIssuerGeneralNames = GeneralNames(GeneralName(subject.toX500Name()))
        val distPoint = DistributionPoint(distPointName, null, crlIssuerGeneralNames)
        val crlDistPoint = CRLDistPoint(arrayOf(distPoint))
        /**
         * Certificate Policies
         */
        val pqInfo = PolicyQualifierInfo("http://test.com/cps")
        val policyInfo = PolicyInformation(PolicyQualifierId.id_qt_cps, DERSequence(pqInfo))
        val policies = CertificatePolicies(policyInfo)
        /**
         * Authority Information Access
         */
        val ocsp = AccessDescription(AccessDescription.id_ad_ocsp, GeneralName(GeneralName.uniformResourceIdentifier, DERIA5String("http://test.com/ocsp")))
        val caIssers = AccessDescription(AccessDescription.id_ad_caIssuers, GeneralName(GeneralName.uniformResourceIdentifier, DERIA5String("http://test.com/caissuers")))
        val aia_ASN = ASN1EncodableVector()
        aia_ASN.add(ocsp)
        aia_ASN.add(caIssers)
        val authorityInfoAccess = DERSequence(aia_ASN)
        /**
         * Name Constraints
         */
        val permittedNameConstraints = arrayOf<GeneralSubtree>() //arrayOf(GeneralSubtree(GeneralName(X500Name("O=WFC, L=San Francisco, C=US"))))
        val excludedNameConstraints = arrayOf(
                GeneralSubtree(GeneralName(rootCert.subjectX500Principal.toX500Name())),
                GeneralSubtree(GeneralName(subject.toX500Name()))
        )

        val builder = JcaX509v3CertificateBuilder(rootPrincipal, serial, notBefore, notAfter, subject, keyPair.public)
                .addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier)
                .addExtension(Extension.basicConstraints, true, basicConstraints)
                .addExtension(Extension.keyUsage, false, keyUsage)
                .addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage)
                .addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier)
//                .addExtension(Extension.cRLDistributionPoints, false, crlDistPoint)
                .addExtension(Extension.certificatePolicies, false, policies)
                .addExtension(Extension.authorityInfoAccess, false, authorityInfoAccess)
                .addExtension(Extension.nameConstraints, true, NameConstraints(permittedNameConstraints, excludedNameConstraints))
        if (issuingCADef.doormanRole)
            builder.addExtension(ASN1ObjectIdentifier(CordaOID.X509_EXTENSION_CORDA_ROLE), false, CertRole.DOORMAN_CA)
        val caCert = builder.build(signer).run {
            require(isValidOn(Date()))
            require(isSignatureValid(JcaContentVerifierProviderBuilder().build(rootKeyPair.public))){"Invalid signature"}
            toJca()
        }

        return Pair(keyPair, caCert)
    }

    private fun createNodeKeystores(certDef: CertDef, issuingCAFile: Path, truststoreFile: Path) {
        val rootDef = certDef.root
        val issuingCADef = certDef.issuingCAs.first()
        val trustStore = loadOrCreateKeyStore(truststoreFile, rootDef.storepass)
        val rootCert = trustStore.getX509Certificate(rootAlias)
        val caKeystore = loadOrCreateKeyStore(issuingCAFile, issuingCADef.nameAndPass.storepass)
        val caPrivateKey =  caKeystore.getSupportedKey(issuingCAAlias, issuingCADef.nameAndPass.keypass)
        val caCert = caKeystore.getX509Certificate(issuingCAAlias)
        val caPublicKey = caCert.publicKey
        val caKeyPair = KeyPair(caPublicKey, caPrivateKey)
        val caSubject = caCert.subjectX500Principal

        val nodeStorepass = certDef.nodes.storepass
        val nodeKeypass = certDef.nodes.keypass
        certDef.nodes.legalNames.forEachIndexed { index, legalName ->
            val nodeOutputFolder = nodeParentOutputFolder() / nameFromLegalName(legalName)
            val nodeKeystoreFile = outputFile(nodeOutputFolder, "nodekeystore.jks")
            val nodeKeystore = loadOrCreateKeyStore(nodeKeystoreFile, nodeStorepass)
            /**
             * Dummy Node CA
             * Only the public cert in the keystore
             * TODO: Find an API to save a cert chain without private key.
             * For now, we use a dummy private key in setKeyEntry. It is sufficient because we just want to show
             * this dummy cert is not used.
             */
            generateNodeCertFromIssuingCA(caKeyPair, caCert, legalName.x500Principal, CertRole.NODE_CA).run {
                val dummyKeyPair = Crypto.generateKeyPair(Crypto.findSignatureScheme(first.public))
                nodeKeystore.setKeyEntry(dummyNodeAlias, dummyKeyPair.private, nodeKeypass.toCharArray(), arrayOf(second, caCert, rootCert))
            }
            /**
             * Legal Identity
             */
            generateNodeCertFromIssuingCA(caKeyPair, caCert, legalName.x500Principal, CertRole.LEGAL_IDENTITY).run {
                nodeKeystore.setKeyEntry(identityAlias, first.private, nodeKeypass.toCharArray(), arrayOf(second, caCert, rootCert))
            }
            nodeKeystore.save(nodeKeystoreFile, nodeStorepass)
            /**
             * TSL
             */
            val sslKeystoreFile = outputFile(nodeOutputFolder, "sslkeystore.jks")
            val sslKeystore = loadOrCreateKeyStore(sslKeystoreFile, nodeStorepass)
            generateNodeCertFromIssuingCA(caKeyPair, caCert, legalName.x500Principal, CertRole.TLS).run {
                sslKeystore.setKeyEntry(sslAliase, first.private, nodeKeypass.toCharArray(), arrayOf(second, caCert, rootCert))
            }
            sslKeystore.save(sslKeystoreFile, nodeStorepass)
        }
    }

    private fun createNodeCSRAndKeystores(csrDef: CSRDef) {
        csrDef.nodes?.forEachIndexed { index, legalName ->
            createNodeCSRAndKeystoresForOneNode(csrDef, legalName)
        }
    }

    private fun createNodeCSRAndKeystoresForOneNode(csrDef: CSRDef, legalName: CordaX500Name) {
        /**
         * For each node, generate 3 pairs of pem and jks
         */
        val alias = csrDef.alias
        val storepass = csrDef.storepass
        val keypass = csrDef.keypass
        val zone = csrDef.zone
        setOf("dummyca", "identity", "tls").forEach {
            val certRole = when(it) {
                "dummyca" -> CertRole.NODE_CA
                "identity" -> CertRole.LEGAL_IDENTITY
                else -> CertRole.TLS
            }
            val (keyPair, csr, cert) = generateCSRAndCert(legalName, certRole, zone)
            val keystoreFile = outputFile("${nameFromLegalName(legalName).toLowerCase()}_$it.jks")
            val keystore = loadOrCreateKeyStore(keystoreFile, storepass)
            keystore.setKeyEntry(alias, keyPair.private, keypass.toCharArray(), arrayOf(cert))
            keystore.save(keystoreFile, storepass)

            /**
             * Note: We save p10 after jks because when the parent folder csrs does not exists, JcaPENWriter errs out
             * while loadOrCreateKeyStore can handle the situation.
             */
            val csrFile = outputFile("${nameFromLegalName(legalName).toLowerCase()}_$it.p10")
            JcaPEMWriter(csrFile.writer()).use {
                it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded))
            }
        }
    }

    private fun generateCSRAndCert(legalName: CordaX500Name, certRole: CertRole, zone: String): Triple<KeyPair, PKCS10CertificationRequest, X509Certificate> {
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

    private fun createNetworkCSRAndKeystore(csrDef: CSRDef, legalName: CordaX500Name, certRole: CertRole) {
        val alias = csrDef.alias
        val storepass = csrDef.storepass
        val keypass = csrDef.keypass
        val zone = csrDef.zone
        val (keyPair, csr, cert) = generateCSRAndCert(legalName, certRole, zone)
        val keystoreFile = outputFile("${nameFromLegalName(legalName).toLowerCase()}.jks")
        val keystore = loadOrCreateKeyStore(keystoreFile, storepass)
        keystore.setKeyEntry(alias, keyPair.private, keypass.toCharArray(), arrayOf(cert))
        keystore.save(keystoreFile, storepass)

        /**
         * Note: We save p10 after jks because when the parent folder csrs does not exists, JcaPENWriter errs out
         * while loadOrCreateKeyStore can handle the situation.
         */
        val csrFile = outputFile("${nameFromLegalName(legalName).toLowerCase()}.p10")
        JcaPEMWriter(csrFile.writer()).use {
            it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded))
        }
    }

    private fun createNetworkCSRAndKeystores(csrDef: CSRDef) {
        val alias = csrDef.alias
        val storepass = csrDef.storepass
        val keypass = csrDef.keypass
        val zone = csrDef.zone
        listOf(csrDef.networkMap!!, csrDef.networkParameters!!).forEachIndexed { index, legalName ->
            val certRole = when (index) {
                0 -> CertRole.NETWORK_MAP
                else -> CertRole.NETWORK_PARAMETERS
            }
            val (keyPair, csr, cert) = generateCSRAndCert(legalName, certRole, zone)
            val keystoreFile = outputFile("${nameFromLegalName(legalName).toLowerCase()}.jks")
            val keystore = loadOrCreateKeyStore(keystoreFile, storepass)
            keystore.setKeyEntry(alias, keyPair.private, keypass.toCharArray(), arrayOf(cert))
            keystore.save(keystoreFile, storepass)

            /**
             * Note: We save p10 after jks because when the parent folder csrs does not exists, JcaPENWriter errs out
             * while loadOrCreateKeyStore can handle the situation.
             */
            val csrFile = outputFile("${nameFromLegalName(legalName).toLowerCase()}.p10")
            JcaPEMWriter(csrFile.writer()).use {
                it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded))
            }
        }
    }

    /**
     * TODO: This has a lot of duplicate codes as createNodeKeystores(...)
     */
    private fun createNotaryKeystores(certDef: CertDef, issuingCAFile: Path, truststoreFile: Path) {
        val rootDef = certDef.root
        val issuingCADef = certDef.issuingCAs.first()
        val trustStore = loadOrCreateKeyStore(truststoreFile, rootDef.storepass)
        val rootCert = trustStore.getX509Certificate(rootAlias)
        val caKeystore = loadOrCreateKeyStore(issuingCAFile, issuingCADef.nameAndPass.storepass)
        val caPrivateKey =  caKeystore.getSupportedKey(issuingCAAlias, issuingCADef.nameAndPass.keypass)
        val caCert = caKeystore.getX509Certificate(issuingCAAlias)
        val caPublicKey = caCert.publicKey
        val caKeyPair = KeyPair(caPublicKey, caPrivateKey)
        val caSubject = caCert.subjectX500Principal

        val nodeStorepass = certDef.notary.storepass
        val nodeKeypass = certDef.notary.keypass
        (certDef.notary.worker_legalNames + certDef.notary.service_legalName).forEachIndexed { index, legalName ->
            val nodeOutputFolder = notaryParentOutputFolder() / nameFromLegalName(legalName)
            val nodeKeystoreFile = outputFile(nodeOutputFolder, "nodekeystore.jks")
            val nodeKeystore = loadOrCreateKeyStore(nodeKeystoreFile, nodeStorepass)
            /**
             * Dummy Node CA
             * Only the public cert in the keystore
             * TODO: Find an API to save a cert chain without private key.
             * For now, we use a dummy private key in setKeyEntry. It is sufficient because we just want to show
             * this dummy cert is not used.
             */
            generateNodeCertFromIssuingCA(caKeyPair, caCert, legalName.x500Principal, CertRole.NODE_CA).run {
                val dummyKeyPair = Crypto.generateKeyPair(Crypto.findSignatureScheme(first.public))
                nodeKeystore.setKeyEntry(dummyNodeAlias, dummyKeyPair.private, nodeKeypass.toCharArray(), arrayOf(second, caCert, rootCert))
            }
            /**
             * Legal Identity
             */
            generateNodeCertFromIssuingCA(caKeyPair, caCert, legalName.x500Principal, CertRole.LEGAL_IDENTITY).run {
                nodeKeystore.setKeyEntry(identityAlias, first.private, nodeKeypass.toCharArray(), arrayOf(second, caCert, rootCert))
            }
            nodeKeystore.save(nodeKeystoreFile, nodeStorepass)
            /**
             * TSL
             */
            val sslKeystoreFile = outputFile(nodeOutputFolder, "sslkeystore.jks")
            val sslKeystore = loadOrCreateKeyStore(sslKeystoreFile, nodeStorepass)
            generateNodeCertFromIssuingCA(caKeyPair, caCert, legalName.x500Principal, CertRole.TLS).run {
                sslKeystore.setKeyEntry(sslAliase, first.private, nodeKeypass.toCharArray(), arrayOf(second, caCert, rootCert))
            }
            sslKeystore.save(sslKeystoreFile, nodeStorepass)
        }
    }

    private fun createNetworKeystore(networkDef: NameAndPass, certDef: CertDef, issuingCAFile: Path, truststoreFile: Path, certRole: CertRole, alias: String) {
        val rootDef = certDef.root
        val issuingCADef = certDef.issuingCAs.last()
        val trustStore = loadOrCreateKeyStore(truststoreFile, rootDef.storepass)
        val rootCert = trustStore.getX509Certificate(rootAlias)
        val caKeystore = loadOrCreateKeyStore(issuingCAFile, issuingCADef.nameAndPass.storepass)
        val caPrivateKey =  caKeystore.getSupportedKey(issuingCAAlias, issuingCADef.nameAndPass.keypass)
        val caCert = caKeystore.getX509Certificate(issuingCAAlias)
        val caPublicKey = caCert.publicKey
        val caKeyPair = KeyPair(caPublicKey, caPrivateKey)
        val caSubject = caCert.subjectX500Principal

        val keystoreFile = outputFile(jksFileNameFromLegalName(networkDef.legalName))
        val keyStore = loadOrCreateKeyStore(keystoreFile, networkDef.storepass)
        generateNodeCertFromIssuingCA(caKeyPair, caCert, networkDef.legalName.x500Principal, certRole).apply {
            keyStore.setKeyEntry(alias, first.private, networkDef.keypass.toCharArray(), arrayOf(second, caCert, rootCert))
        }
        keyStore.save(keystoreFile, networkDef.storepass)
    }

    /**
     * Either Dummy Node CA, Legal Identity or TSL
     * Even NetworkMap and NetworkParameters use it
     * NOTE: SSL connection would fail with java.security.cert.CRLException: Empty input:
     *  if we add Extension.cRLDistributionPoints.
     *  We may have to learn how to set up CDP.
     */
    private fun generateNodeCertFromIssuingCA(caKeyPair: KeyPair, caCert: X509Certificate, subjectPrincipal: X500Principal, certRole: CertRole): Pair<KeyPair, X509Certificate> {
        val caPrincipal = caCert.subjectX500Principal
        val caSignatureScheme = Crypto.findSignatureScheme(caKeyPair.public)  //Crypto.ECDSA_SECP256R1_SHA256
        val signer = ContentSignerBuilder.build(caSignatureScheme, caKeyPair.private, Crypto.findProvider(caSignatureScheme.providerName))

        val signatureScheme = eccScheme //Crypto.ECDSA_SECP256R1_SHA256 //caSignatureScheme
        val keyPair = Crypto.generateKeyPair(signatureScheme)
        val serial = BigInteger.valueOf(random63BitValue())
        val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.public.encoded))
        val subjectKeyIdentifier = BcX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKeyInfo)
        val authorityKeyIdentifier = JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caKeyPair.public)
        /**
         * Validity Window
         */
        val calendar = GregorianCalendar()
        calendar.set(2019, Calendar.JANUARY, 1, 0, 0, 0)
        val notBefore: Date = calendar.time
        calendar.set(2020, Calendar.DECEMBER, 31, 23, 59, 59)
//        var notAfter: Date = calendar.time
        val notAfter: Date = calendar.time
        /**
         * Basic Constraint
         */
        val basicConstraints = BasicConstraints(false)
        /**
         * Key Usage
         */
        // This is for Legal Identity, and Node CA
        var keyUsage = KeyUsage(KeyUsage.digitalSignature)
        // this is for TLS
        if (certRole == CertRole.TLS) {
            keyUsage = KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment or KeyUsage.keyAgreement)
//            calendar.set(2019, Calendar.APRIL, 15, 9, 0, 0)
//            notAfter = calendar.time
        }
//        else if (certRole == CertRole.LEGAL_IDENTITY) {
//            calendar.set(2019, Calendar.APRIL, 15, 9, 0, 0)
//            notAfter = calendar.time
//        }
        /**
         * Extended Key Usage
         */
        val extendedKeyUsage = ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.anyExtendedKeyUsage))
        /**
         * CRL Distribution Point
         */
        val distPointName = DistributionPointName(GeneralNames(GeneralName(GeneralName.uniformResourceIdentifier, "http://test.com/crl")))
        val crlIssuerGeneralNames = GeneralNames(GeneralName(caPrincipal.toX500Name()))
        val distPoint = DistributionPoint(distPointName, null, crlIssuerGeneralNames)
        val crlDistPoint = CRLDistPoint(arrayOf(distPoint))

        val builder = JcaX509v3CertificateBuilder(caPrincipal, serial, notBefore, notAfter, subjectPrincipal, keyPair.public)
                .addExtension(ASN1ObjectIdentifier(CordaOID.X509_EXTENSION_CORDA_ROLE), false, certRole)
                .addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier)
                .addExtension(Extension.basicConstraints, true, basicConstraints)
                .addExtension(Extension.keyUsage, false, keyUsage)
                .addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage)
                .addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier)
//                .addExtension(Extension.cRLDistributionPoints, false, crlDistPoint)
        val cert = builder.build(signer).run {
            require(isValidOn(Date()))
            require(isSignatureValid(JcaContentVerifierProviderBuilder().build(caKeyPair.public))){"Invalid signature"}
            toJca()
        }
        return Pair(keyPair, cert)
    }

    private fun createNodeJKSs(csrDef: CSRDef) {
        csrDef.nodes?.forEachIndexed { index, legalName ->
            createNodeSSLJKS(csrDef, legalName)
            createNodeNodeJKS(csrDef, legalName)
        }
    }

    private fun createNodeSSLJKS(csrDef: CSRDef, legalName: CordaX500Name, isOnNode: Boolean = false) {
        val partyName = nameFromLegalName(legalName)
        val partyLabel = nameFromLegalNameInLowerCase(legalName)
        val sourceStorepass = csrDef.storepass
        val sourceKeypass = csrDef.keypass
        val targetStorepass = keystorepass
        val targetKeypass = keystorepass
        val sourceAlias = csrDef.alias
        val targetAlias = sslAliase

        val cerFile = outputFile(cerFolder!!/"cer", "${partyLabel}_tls.cer")
        val sourceJKSFile = outputFile(csrFolder!!, "${partyLabel}_tls.jks")
        val targetJKSFile = if (isOnNode) outputFile(outputFolder!!, "sslkeystore.jks") else outputFile(outputFolder!!, "${partyName}/sslkeystore.jks")

        val sourceKetStore = loadOrCreateKeyStore(sourceJKSFile, sourceStorepass)
        val privateKey = sourceKetStore.getKey(sourceAlias, sourceKeypass.toCharArray())
        val targetKeyStore = loadOrCreateKeyStore(targetJKSFile, targetStorepass)

        val rootCert = X509Utilities.loadCertificateFromPEMFile(outputFile(cerFolder!!, "rca.cer"))
        val issuingCA2Cert = X509Utilities.loadCertificateFromPEMFile(outputFile(cerFolder!!, "ica1.cer"))
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)

        targetKeyStore.setKeyEntry(targetAlias, privateKey, targetKeypass.toCharArray(), arrayOf(cert, issuingCA2Cert, rootCert))

        targetKeyStore.save(targetJKSFile, targetStorepass)
    }

    private fun createNodeNodeJKS(csrDef: CSRDef, legalName: CordaX500Name, isOnNode: Boolean = false) {
        val partyName = nameFromLegalName(legalName)
        val partyLabel = nameFromLegalNameInLowerCase(legalName)
        val sourceStorepass = csrDef.storepass
        val sourceKeypass = csrDef.keypass
        val targetStorepass = keystorepass
        val targetKeypass = keystorepass
        val sourceAlias = csrDef.alias
        val targetAlias_identity = identityAlias
        val targetAlias_dummy = dummyNodeAlias

        val cerFile_identity = outputFile(cerFolder!!/"cer","${partyLabel}_identity.cer")
        val cerFile_dummy = outputFile(cerFolder!!/"cer","${partyLabel}_dummyca.cer")
        val sourceJKSFile_identity = outputFile(csrFolder!!,"${partyLabel}_identity.jks")
        val sourceJKSFile_dummy = outputFile(csrFolder!!, "${partyLabel}_dummyca.jks")
        val targetJKSFile = if (isOnNode) outputFile(outputFolder!!,"nodekeystore.jks") else outputFile(outputFolder!!,"${partyName}/nodekeystore.jks")

        val sourceKetStore_identity = loadOrCreateKeyStore(sourceJKSFile_identity, sourceStorepass)
        val sourceKetStore_dummy = loadOrCreateKeyStore(sourceJKSFile_dummy, sourceStorepass)
        val privateKey_identity = sourceKetStore_identity.getKey(sourceAlias, sourceKeypass.toCharArray())
        val privateKey_dummy = sourceKetStore_dummy.getKey(sourceAlias, sourceKeypass.toCharArray())
        val targetKeyStore = loadOrCreateKeyStore(targetJKSFile, targetStorepass)

        val rootCert = X509Utilities.loadCertificateFromPEMFile(outputFile(cerFolder!!, "rca.cer"))
        val issuingCA2Cert = X509Utilities.loadCertificateFromPEMFile(outputFile(cerFolder!!, "ica1.cer"))
        val cert_identity = X509Utilities.loadCertificateFromPEMFile(cerFile_identity)
        val cert_dummy = X509Utilities.loadCertificateFromPEMFile(cerFile_dummy)

        targetKeyStore.setKeyEntry(targetAlias_dummy, privateKey_dummy, targetKeypass.toCharArray(), arrayOf(cert_dummy, issuingCA2Cert, rootCert))
        targetKeyStore.setKeyEntry(targetAlias_identity, privateKey_identity, targetKeypass.toCharArray(), arrayOf(cert_identity, issuingCA2Cert, rootCert))

        targetKeyStore.save(targetJKSFile, targetStorepass)
    }

    private fun createNetworkJKS(csrDef: CSRDef, targetAlias: String) {
        val storepass = networkkeystorepass
        val keypass = networkkeystorepass
        val sourceAlias = csrDef.alias
        val legalName = if (targetAlias == "networkmap") csrDef.networkMap!! else csrDef.networkParameters!!
        val cerFile = outputFile(cerFolder!! / "cer", nameFromLegalNameInLowerCase(legalName) + ".cer")
        val sourceJKSFile = outputFile(csrFolder!!, jksFileNameFromLegalName(legalName))
        val targetJKSFile = outputFile(outputFolder!!, jksFileNameFromLegalName(legalName))

        val sourceKetStore = loadOrCreateKeyStore(sourceJKSFile, storepass)
        val privateKey = sourceKetStore.getKey(sourceAlias, keypass.toCharArray())
        val targetKeyStore = loadOrCreateKeyStore(targetJKSFile, storepass)

        val rootCert = X509Utilities.loadCertificateFromPEMFile(outputFile(cerFolder!!,"rca.cer"))
        val issuingCA2Cert = X509Utilities.loadCertificateFromPEMFile(outputFile(cerFolder!!,"ica2.cer"))
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)

        targetKeyStore.setKeyEntry(targetAlias, privateKey, keypass.toCharArray(), arrayOf(cert, issuingCA2Cert, rootCert))

        targetKeyStore.save(targetJKSFile, storepass)
    }

    private fun passCertConfig(config: Config) : CertDef {
        val zone = if (config.hasPath("zone")) config.getString("zone") else "DEV"
        val root = NameAndPass(
                legalName = CordaX500Name.parse(config.getString("root.legalName") ?: "O=RootCA, L=Dallas, C=US"),
                storepass = config.getString("root.storepass") ?: "trustpass",
                keypass = config.getString("root.keypass") ?: "trustpass"
        )
        val issuingCAs: List<IssuingCA> = config.getConfigList("issuingCAs").mapIndexed { index, issuingCA ->
            IssuingCA(
                    NameAndPass(
                            legalName = CordaX500Name.parse(issuingCA.getString("legalName") ?: "O=IssuingCA${index+1}, L=Dallas, C=US"),
                            storepass = issuingCA.getString("storepass") ?: "trustpass",
                            keypass = issuingCA.getString("keypass") ?: "trustpass"
                    ),
                    doormanRole = issuingCA.getBoolean("doormanRole") //?: if (index == 0) true else false
            )
        }
        val nodes = Nodes(
                legalNames = config.getStringList("nodes.legalNames").map { CordaX500Name.parse(it) },
                storepass = config.getString("nodes.storepass") ?: "cordacadevpass",
                keypass = config.getString("nodes.keypass") ?: "cordacadevpass"
        )
        val notary = Notary(
            service_legalName = CordaX500Name.parse(config.getString("notary.service_legalName")),
            worker_legalNames = config.getStringList("notary.worker_legalNames").map { CordaX500Name.parse(it) },
            storepass = config.getString("notary.storepass") ?: "cordacadevpass",
            keypass = config.getString("notary.keypass") ?: "cordacadevpass"
        )
        val networkMap = NameAndPass(
                legalName = CordaX500Name.parse(config.getString("networkMap.legalName") ?: "O=NetworkMap, L=Dallas, C=US"),
                storepass = config.getString("networkMap.storepass") ?: "trustpass",
                keypass = config.getString("networkMap.keypass") ?: "trustpass"
        )
        val networkParameters = NameAndPass(
                legalName = CordaX500Name.parse(config.getString("networkParameters.legalName") ?: "O=NetworkParameters, L=Dallas, C=US"),
                storepass = config.getString("networkParameters.storepass") ?: "trustpass",
                keypass = config.getString("networkParameters.keypass") ?: "trustpass"
        )

        return CertDef(
                zone,
                root,
                issuingCAs,
                nodes,
                notary,
                networkMap,
                networkParameters
        )
    }

    private fun certDefFromConfig(file: Path) : CertDef {
        val parseOptions = ConfigParseOptions.defaults().setAllowMissing(true)
        val config = ConfigFactory.parseFile(file.toFile(), parseOptions).resolve()
        return passCertConfig(config)
    }

    private fun passCSRConfig(config: Config) : CSRDef {
        val zone = if (config.hasPath("zone")) config.getString("zone") else "DEV"
        val nodes = if (config.hasPath("nodes")) config.getStringList("nodes").map { CordaX500Name.parse(it) } else emptyList()
        return CSRDef (
                zone = zone,
                nodes = nodes,
                networkMap = if (config.hasPath("networkMap")) CordaX500Name.parse(config.getString("networkMap")) else null,
                networkParameters = if (config.hasPath("networkParameters")) CordaX500Name.parse(config.getString("networkParameters")) else null,
                alias = config.getString("alias"),
                storepass = config.getString("storepass"),
                keypass = config.getString("keypass")
        )
    }

    private fun csrDefFromConfig(file: Path) : CSRDef {
        val parseOptions = ConfigParseOptions.defaults().setAllowMissing(true)
        val config = ConfigFactory.parseFile(file.toFile(), parseOptions).resolve()
        return passCSRConfig(config)
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

    private fun nameFromLegalName(legalName: CordaX500Name) = ("${legalName.commonName ?: legalName.organisationUnit ?: legalName.organisation}")//.toLowerCase()
    private fun nameFromLegalNameInLowerCase(legalName: CordaX500Name) = "${nameFromLegalName(legalName)}".toLowerCase()
    private fun jksFileNameFromLegalName(legalName: CordaX500Name) = nameFromLegalNameInLowerCase(legalName) + ".jks"
//    private fun jksFileNameFromLegalName(legalName: CordaX500Name) = ("${nameFromLegalName(legalName)}.jks").toLowerCase()
    private fun outputFile(name: String) = outputFolder!! / name
    private fun outputFile(parent: Path, name: String) = parent / name
    private fun nodeParentOutputFolder() = outputFolder!! / "nodes"
    private fun notaryParentOutputFolder() = outputFolder!! / "notary"
}