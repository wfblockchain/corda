package com.wfc.cert

import com.typesafe.config.ConfigFactory
import com.typesafe.config.ConfigParseOptions
import com.wfc.cert.Common.Companion.csrDefFromConfig
import com.wfc.cert.Common.Companion.inputParameter
import net.corda.core.crypto.internal.AliasPrivateKey
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.CertRole
import net.corda.nodeapi.internal.crypto.save
import java.nio.file.Path
import java.security.Provider

fun generateCSRs() {
    val configFile = inputParameter.configFile!!
    val outputFolder = inputParameter.outputFolder!!

    val csrDef = csrDefFromConfig(configFile)
    createNodeCSRAndKeystores(csrDef, outputFolder)
    if (csrDef.networkMap != null) createNetworkCSRAndKeystore_w_CSRBuilder(csrDef, csrDef.networkMap, CertRole.NETWORK_MAP, outputFolder)
    if (csrDef.networkParameters != null) createNetworkCSRAndKeystore_w_CSRBuilder(csrDef, csrDef.networkParameters, CertRole.NETWORK_PARAMETERS, outputFolder)
//        createNetworkCSRAndKeystores(csrDef)
}

fun generateCSRsOnNode(hasHSM: Boolean) {
    println("generateCSRsOnNode - start with hasHSM = $hasHSM")
    val configFile = inputParameter.configFile!!
    val base_directory = inputParameter.base_directory!!
    val outputFolder = inputParameter.outputFolder!!

    val csrDef = csrDefFromConfig(configFile)
    val parseOptions = ConfigParseOptions.defaults().setAllowMissing(true)
    val nodeConfig = ConfigFactory.parseFile(Common.outputFile(base_directory, "node.conf").toFile(), parseOptions).resolve()
    val legalName = CordaX500Name.parse(nodeConfig.getString("myLegalName"))
    createNodeCSRAndKeystoresForOneNode_w_CSRBuilder(csrDef, legalName, outputFolder, hasHSM)
}

/**
 * hasHSM = ture: what provider
 */
private fun createNodeCSRAndKeystoresForOneNode_w_CSRBuilder(csrDef: CertGen.CSRDef, legalName: CordaX500Name, outputFolder: Path, hasHSM: Boolean = false) {
    println("createNodeCSRAndKeystoresForOneNode - start with hasHSM = $hasHSM")
    /**
     * For each node, generate 3 pairs of pem and jks
     */
    val alias = csrDef.alias
    val storepass = csrDef.storepass
    val keypass = csrDef.keypass
    val zone = csrDef.zone
    val provider: Provider = HSM.getProvider(hasHSM, inputParameter.hsm_provider, inputParameter.hsm_config_file_name)
    val jksProvider = HSM.getProvider(false, null, null)
    setOf("dummyca", "identity", "tls").forEach {certFor ->
        val certRole = when(certFor) {
            "dummyca" -> CertRole.NODE_CA
            "identity" -> CertRole.LEGAL_IDENTITY
            else -> CertRole.TLS
        }
        /**
         * TLS still uses JKS independent of hasHSM
         * When Corda supports HSM for TLS, we can set useJKS = false
         * so that all private keys will be in HSM
         */
        val useJKS: Boolean = certFor == "tls" || !hasHSM
        val providerForIt = if (useJKS) jksProvider else provider
        val keyStoreType = if (useJKS) "JKS" else "PKCS11"

        val keystoreFile = Common.outputFile(outputFolder, "${Common.nameFromLegalName(legalName).toLowerCase()}_$certFor.jks")
        val builder = CSRBuilder(keyStoreType, providerForIt, "EC", Common.eccCurve, 0, Common.eccScheme, legalName, certRole, zone).apply {
            if (useJKS) initialize(keystoreFile, storepass)
            else initialize(inputParameter.hsm_login!!)
        }
        val builderData = builder.build()
        if (useJKS) {
            builderData.keyStore.setKeyEntry(alias, builderData.keyPair.private, keypass.toCharArray(), arrayOf(builderData.cert))
            builderData.keyStore.save(keystoreFile, storepass)
            // Save csr in p10 file
            saveCSRFile(builderData.csr, legalName, outputFolder, certFor)
        }
        else {
            val aliasForHSM = Common.aliasFull(if (certFor == "dummyca") Common.dummyNodeAlias else Common.identityAlias, legalName, zone)
            // Save private key and cert in HSM
            builderData.keyStore.deleteEntry(aliasForHSM)
            builderData.keyStore.setKeyEntry(aliasForHSM, builderData.keyPair.private, null, arrayOf(builderData.cert))
            // Save AliasPrivateKey and cert in JKS
            Common.saveCertInJKSKeyStoreFile(builderData.cert, legalName, outputFolder, AliasPrivateKey(aliasForHSM), alias, keypass, storepass, certFor)
            // Save csr in p10 file
            saveCSRFile(builderData.csr, legalName, outputFolder, certFor)
        }
        // The following is replaced by the above
        /*
        val (keyPair, csr, cert) = Common.generateCSRAndCert(legalName, certRole, zone, hasHSM && (it == "identity"|| it == "tls"))
        val keystore = loadOrCreateKeyStore(keystoreFile, storepass)
        keystore.setKeyEntry(alias, keyPair.private, keypass.toCharArray(), arrayOf(cert))
        keystore.save(keystoreFile, storepass)
        println("createNodeCSRAndKeystoresForOneNode - keystore.save in ${keystoreFile.fileName} for $it - done")

        /**
         * Note: We save p10 after jks because when the parent folder csrs does not exists, JcaPENWriter errs out
         * while loadOrCreateKeyStore can handle the situation.
         */
        val csrFile = Common.outputFile(outputFolder!!, "${Common.nameFromLegalName(legalName).toLowerCase()}_$it.p10")
        JcaPEMWriter(csrFile.writer()).use {
            it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded))
        }
        println("createNodeCSRAndKeystoresForOneNode - JcaPEMWriter in ${csrFile.fileName} for $it - done")
        */
    }
}

private fun createNodeCSRAndKeystores(csrDef: CertGen.CSRDef, outputFolder: Path) {
    csrDef.nodes?.forEachIndexed { index, legalName ->
        createNodeCSRAndKeystoresForOneNode_w_CSRBuilder(csrDef, legalName, outputFolder)
    }
}

private fun createNetworkCSRAndKeystore_w_CSRBuilder(csrDef: CertGen.CSRDef, legalName: CordaX500Name, certRole: CertRole, outputFolder: Path) {
    val alias = csrDef.alias
    val storepass = csrDef.storepass
    val keypass = csrDef.keypass
    val zone = csrDef.zone
    val provider = HSM.getProvider(false, null, null)
    val keyStoreType = "JKS"
    val keystoreFile = Common.outputFile(outputFolder, "${Common.nameFromLegalName(legalName).toLowerCase()}.jks")
    val builder = CSRBuilder(keyStoreType, provider, "EC", Common.eccCurve, 0, Common.eccScheme, legalName, certRole, zone).apply {
        initialize(keystoreFile, storepass)
    }
    val builderData = builder.build()
    builderData.keyStore.setKeyEntry(alias, builderData.keyPair.private, keypass.toCharArray(), arrayOf(builderData.cert))
    builderData.keyStore.save(keystoreFile, storepass)
    // Save csr in p10 file
    saveCSRFile(builderData.csr, legalName, outputFolder, null)
    // The following is replaced by the above
    /*
    val (keyPair, csr, cert) = Common.generateCSRAndCert(legalName, certRole, zone)
    val keystore = loadOrCreateKeyStore(keystoreFile, storepass)
    keystore.setKeyEntry(alias, keyPair.private, keypass.toCharArray(), arrayOf(cert))
    keystore.save(keystoreFile, storepass)

    /**
     * Note: We save p10 after jks because when the parent folder csrs does not exists, JcaPENWriter errs out
     * while loadOrCreateKeyStore can handle the situation.
     */
    val csrFile = Common.outputFile(outputFolder!!, "${Common.nameFromLegalName(legalName).toLowerCase()}.p10")
    JcaPEMWriter(csrFile.writer()).use {
        it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded))

    }
    */
}


/*
@Deprecated(message = "", replaceWith = ReplaceWith("createNodeCSRAndKeystoresForOneNode_w_CSRBuilder"))
private fun createNodeCSRAndKeystoresForOneNode(csrDef: CertGen.CSRDef, legalName: CordaX500Name, outputFolder: Path, hasHSM: Boolean = false) {
    println("createNodeCSRAndKeystoresForOneNode - start with hasHSM = $hasHSM")
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
        val (keyPair, csr, cert) = Common.generateCSRAndCert(legalName, certRole, zone, hasHSM && (it == "identity"|| it == "tls"))
        val keystoreFile = Common.outputFile(outputFolder, "${Common.nameFromLegalName(legalName).toLowerCase()}_$it.jks")
        val keystore = loadOrCreateKeyStore(keystoreFile, storepass)
        keystore.setKeyEntry(alias, keyPair.private, keypass.toCharArray(), arrayOf(cert))
        keystore.save(keystoreFile, storepass)
        println("createNodeCSRAndKeystoresForOneNode - keystore.save in ${keystoreFile.fileName} for $it - done")

        /**
         * Note: We save p10 after jks because when the parent folder csrs does not exists, JcaPENWriter errs out
         * while loadOrCreateKeyStore can handle the situation.
         */
        val csrFile = Common.outputFile(outputFolder!!, "${Common.nameFromLegalName(legalName).toLowerCase()}_$it.p10")
        JcaPEMWriter(csrFile.writer()).use {
            it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded))
        }
        println("createNodeCSRAndKeystoresForOneNode - JcaPEMWriter in ${csrFile.fileName} for $it - done")
    }
}
*/

/*
@Deprecated(message = "", replaceWith = ReplaceWith("createNetworkCSRAndKeystore"))
private fun createNetworkCSRAndKeystores(csrDef: CertGen.CSRDef, outputFolder: Path) {
    val alias = csrDef.alias
    val storepass = csrDef.storepass
    val keypass = csrDef.keypass
    val zone = csrDef.zone
    listOf(csrDef.networkMap!!, csrDef.networkParameters!!).forEachIndexed { index, legalName ->
        val certRole = when (index) {
            0 -> CertRole.NETWORK_MAP
            else -> CertRole.NETWORK_PARAMETERS
        }
        val (keyPair, csr, cert) = Common.generateCSRAndCert(legalName, certRole, zone)
        val keystoreFile = Common.outputFile(outputFolder, "${Common.nameFromLegalName(legalName).toLowerCase()}.jks")
        val keystore = loadOrCreateKeyStore(keystoreFile, storepass)
        keystore.setKeyEntry(alias, keyPair.private, keypass.toCharArray(), arrayOf(cert))
        keystore.save(keystoreFile, storepass)

        /**
         * Note: We save p10 after jks because when the parent folder csrs does not exists, JcaPENWriter errs out
         * while loadOrCreateKeyStore can handle the situation.
         */
        val csrFile = Common.outputFile(outputFolder, "${Common.nameFromLegalName(legalName).toLowerCase()}.p10")
        JcaPEMWriter(csrFile.writer()).use {
            it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded))
        }
    }
}
*/

/*
@Deprecated(message = "", replaceWith = ReplaceWith("createNetworkCSRAndKeystore_w_CSRBuilder"))
private fun createNetworkCSRAndKeystore(csrDef: CertGen.CSRDef, legalName: CordaX500Name, certRole: CertRole, outputFolder: Path) {
    val alias = csrDef.alias
    val storepass = csrDef.storepass
    val keypass = csrDef.keypass
    val zone = csrDef.zone
    val (keyPair, csr, cert) = Common.generateCSRAndCert(legalName, certRole, zone)
    val keystoreFile = Common.outputFile(outputFolder, "${Common.nameFromLegalName(legalName).toLowerCase()}.jks")
    val keystore = loadOrCreateKeyStore(keystoreFile, storepass)
    keystore.setKeyEntry(alias, keyPair.private, keypass.toCharArray(), arrayOf(cert))
    keystore.save(keystoreFile, storepass)

    /**
     * Note: We save p10 after jks because when the parent folder csrs does not exists, JcaPENWriter errs out
     * while loadOrCreateKeyStore can handle the situation.
     */
    val csrFile = Common.outputFile(outputFolder!!, "${Common.nameFromLegalName(legalName).toLowerCase()}.p10")
    JcaPEMWriter(csrFile.writer()).use {
        it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded))
    }
}
*/