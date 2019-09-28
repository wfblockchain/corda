package com.wfc.cert

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import com.typesafe.config.ConfigParseOptions
import com.wfc.cert.Common.Companion.csrDefFromConfig
import com.wfc.cert.Common.Companion.inputParameter
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.CertRole
import net.corda.core.internal.writer
import net.corda.nodeapi.internal.crypto.loadOrCreateKeyStore
import net.corda.nodeapi.internal.crypto.save
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.util.io.pem.PemObject
import java.nio.file.Path

fun generateCSRs() {
    val configFile = inputParameter.configFile!!
    val outputFolder = inputParameter.outputFolder!!

    val csrDef = csrDefFromConfig(configFile)
    createNodeCSRAndKeystores(csrDef, outputFolder)
    if (csrDef.networkMap != null) createNetworkCSRAndKeystore(csrDef, csrDef.networkMap, CertRole.NETWORK_MAP, outputFolder)
    if (csrDef.networkParameters != null) createNetworkCSRAndKeystore(csrDef, csrDef.networkParameters, CertRole.NETWORK_PARAMETERS, outputFolder)
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
    createNodeCSRAndKeystoresForOneNode(csrDef, legalName, outputFolder, hasHSM)
}

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

private fun createNodeCSRAndKeystores(csrDef: CertGen.CSRDef, outputFolder: Path) {
    csrDef.nodes?.forEachIndexed { index, legalName ->
        createNodeCSRAndKeystoresForOneNode(csrDef, legalName, outputFolder)
    }
}


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
