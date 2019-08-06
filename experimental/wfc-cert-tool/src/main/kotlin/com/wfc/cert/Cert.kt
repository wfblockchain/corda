package com.wfc.cert

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import com.typesafe.config.ConfigParseOptions
import com.wfc.cert.Common.Companion.dummyNodeAlias
import com.wfc.cert.Common.Companion.eccScheme
import com.wfc.cert.Common.Companion.generateCSRAndCert
import com.wfc.cert.Common.Companion.identityAlias
import com.wfc.cert.Common.Companion.inputParameter
import com.wfc.cert.Common.Companion.issuingCAAlias
import com.wfc.cert.Common.Companion.jksFileNameFromLegalName
import com.wfc.cert.Common.Companion.nameFromLegalName
import com.wfc.cert.Common.Companion.networkmapAlias
import com.wfc.cert.Common.Companion.networkparametersAlias
import com.wfc.cert.Common.Companion.nodeParentOutputFolder
import com.wfc.cert.Common.Companion.notaryParentOutputFolder
import com.wfc.cert.Common.Companion.outputFile
import com.wfc.cert.Common.Companion.rootAlias
import com.wfc.cert.Common.Companion.rsaScheme
import com.wfc.cert.Common.Companion.sslAliase
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
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.bc.BcX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.util.io.pem.PemObject
import java.math.BigInteger
import java.nio.file.Path
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.util.*
import javax.security.auth.x500.X500Principal

fun generateCerts() {
    val configFile = inputParameter.configFile!!
    val outputFolder = inputParameter.outputFolder!!
    val certDef = certDefFromConfig(configFile)
    val (rootFile, trustStoreFile) = createRootAndTrustKeystores(certDef, outputFolder)
    val (issuingCA1File, issuingCA2File) = createIssuingCAKeystores(certDef, rootFile, outputFolder)
    createNodeKeystores(certDef, issuingCA1File, trustStoreFile, outputFolder)
    createNotaryKeystores(certDef, issuingCA1File, trustStoreFile, outputFolder)
    createNetworKeystore(certDef.networkMap, certDef, issuingCA2File, trustStoreFile, CertRole.NETWORK_MAP, networkmapAlias, outputFolder)
    createNetworKeystore(certDef.networkParameters, certDef, issuingCA2File, trustStoreFile, CertRole.NETWORK_PARAMETERS, networkparametersAlias, outputFolder)
}

private fun createRootAndTrustKeystores(certDef: CertGen.CertDef, outputFolder: Path): Pair<Path, Path> {
    val rootDef = certDef.root
    val zone = certDef.zone
    val rootcaFile = outputFile(outputFolder, jksFileNameFromLegalName(rootDef.legalName))
    val (keyPair, cert) = generateRootCACert(rootDef, zone)
    val rootCAKeystore = loadOrCreateKeyStore(rootcaFile, rootDef.storepass)
    rootCAKeystore.setKeyEntry(rootAlias, keyPair.private, rootDef.keypass.toCharArray(), arrayOf(cert))
    rootCAKeystore.save(rootcaFile, rootDef.storepass)

    /**
     * truststore
     */
    val rootCert = rootCAKeystore.getX509Certificate(rootAlias)
    val truststoreFile = outputFile(outputFolder,"truststore.jks")
    val truststore = loadOrCreateKeyStore(truststoreFile, rootDef.storepass)
    truststore.setCertificateEntry(rootAlias, rootCert)
    truststore.save(truststoreFile, rootDef.storepass)

    return Pair(rootcaFile, truststoreFile)
}

private fun generateRootCACert(rootDef: CertGen.NameAndPass, zone: String): Pair<KeyPair, X509Certificate> {
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

private fun createIssuingCAKeystores(certDef: CertGen.CertDef, rootFile: Path, outputFolder: Path): Pair<Path, Path> {
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
        val keystoreFile = outputFile(outputFolder, jksFileNameFromLegalName(issuingCA.nameAndPass.legalName))
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

private fun generateIssuingCACertFromRootCA(issuingCADef: CertGen.IssuingCA, rootKeyPair: KeyPair, rootCert: X509Certificate): Pair<KeyPair, X509Certificate> {
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

private fun createNodeKeystores(certDef: CertGen.CertDef, issuingCAFile: Path, truststoreFile: Path, outputFolder: Path) {
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
        val nodeOutputFolder = nodeParentOutputFolder(outputFolder) / nameFromLegalName(legalName)
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

/**
 * TODO: This has a lot of duplicate codes as createNodeKeystores(...)
 */
private fun createNotaryKeystores(certDef: CertGen.CertDef, issuingCAFile: Path, truststoreFile: Path, outputFolder: Path) {
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
        val nodeOutputFolder = notaryParentOutputFolder(outputFolder) / nameFromLegalName(legalName)
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

private fun createNetworKeystore(networkDef: CertGen.NameAndPass, certDef: CertGen.CertDef, issuingCAFile: Path, truststoreFile: Path, certRole: CertRole, alias: String, outputFolder: Path) {
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

    val keystoreFile = outputFile(outputFolder, jksFileNameFromLegalName(networkDef.legalName))
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

private fun certDefFromConfig(file: Path) : CertGen.CertDef {
    val parseOptions = ConfigParseOptions.defaults().setAllowMissing(true)
    val config = ConfigFactory.parseFile(file.toFile(), parseOptions).resolve()
    return passCertConfig(config)
}

private fun passCertConfig(config: Config) : CertGen.CertDef {
    val zone = if (config.hasPath("zone")) config.getString("zone") else "DEV"
    val root = CertGen.NameAndPass(
            legalName = CordaX500Name.parse(config.getString("root.legalName") ?: "O=RootCA, L=Dallas, C=US"),
            storepass = config.getString("root.storepass") ?: "trustpass",
            keypass = config.getString("root.keypass") ?: "trustpass"
    )
    val issuingCAs: List<CertGen.IssuingCA> = config.getConfigList("issuingCAs").mapIndexed { index, issuingCA ->
        CertGen.IssuingCA(
                CertGen.NameAndPass(
                        legalName = CordaX500Name.parse(issuingCA.getString("legalName") ?: "O=IssuingCA${index + 1}, L=Dallas, C=US"),
                        storepass = issuingCA.getString("storepass") ?: "trustpass",
                        keypass = issuingCA.getString("keypass") ?: "trustpass"
                ),
                doormanRole = issuingCA.getBoolean("doormanRole") //?: if (index == 0) true else false
        )
    }
    val nodes = CertGen.Nodes(
            legalNames = config.getStringList("nodes.legalNames").map { CordaX500Name.parse(it) },
            storepass = config.getString("nodes.storepass") ?: "cordacadevpass",
            keypass = config.getString("nodes.keypass") ?: "cordacadevpass"
    )
    val notary = CertGen.Notary(
            service_legalName = CordaX500Name.parse(config.getString("notary.service_legalName")),
            worker_legalNames = config.getStringList("notary.worker_legalNames").map { CordaX500Name.parse(it) },
            storepass = config.getString("notary.storepass") ?: "cordacadevpass",
            keypass = config.getString("notary.keypass") ?: "cordacadevpass"
    )
    val networkMap = CertGen.NameAndPass(
            legalName = CordaX500Name.parse(config.getString("networkMap.legalName") ?: "O=NetworkMap, L=Dallas, C=US"),
            storepass = config.getString("networkMap.storepass") ?: "trustpass",
            keypass = config.getString("networkMap.keypass") ?: "trustpass"
    )
    val networkParameters = CertGen.NameAndPass(
            legalName = CordaX500Name.parse(config.getString("networkParameters.legalName") ?: "O=NetworkParameters, L=Dallas, C=US"),
            storepass = config.getString("networkParameters.storepass") ?: "trustpass",
            keypass = config.getString("networkParameters.keypass") ?: "trustpass"
    )

    return CertGen.CertDef(
            zone,
            root,
            issuingCAs,
            nodes,
            notary,
            networkMap,
            networkParameters
    )
}
