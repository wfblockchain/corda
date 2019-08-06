package com.wfc.cert

import com.typesafe.config.ConfigFactory
import com.typesafe.config.ConfigParseOptions
import com.wfc.cert.Common.Companion.inputParameter
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.div
import net.corda.nodeapi.internal.crypto.X509Utilities
import net.corda.nodeapi.internal.crypto.loadOrCreateKeyStore
import net.corda.nodeapi.internal.crypto.save

fun createJKSs() {
    val configFile = inputParameter.configFile!!

    val csrDef = Common.csrDefFromConfig(configFile)
    createNodeJKSs(csrDef)
    if (csrDef.networkMap != null) createNetworkJKS(csrDef, Common.networkmapAlias)
    if (csrDef.networkParameters != null) createNetworkJKS(csrDef, Common.networkparametersAlias)
}

fun createJKSsOnNode() {
    val configFile = Common.inputParameter.configFile!!
    val base_directory = Common.inputParameter.base_directory!!

    val csrDef = Common.csrDefFromConfig(configFile)
    val parseOptions = ConfigParseOptions.defaults().setAllowMissing(true)
    val nodeConfig = ConfigFactory.parseFile(Common.outputFile(base_directory, "node.conf").toFile(), parseOptions).resolve()
    val legalName = CordaX500Name.parse(nodeConfig.getString("myLegalName"))
    createNodeSSLJKS(csrDef, legalName, true)
    createNodeNodeJKS(csrDef, legalName, true)
}

private fun createNodeJKSs(csrDef: CertGen.CSRDef) {
    csrDef.nodes?.forEachIndexed { index, legalName ->
        createNodeSSLJKS(csrDef, legalName)
        createNodeNodeJKS(csrDef, legalName)
    }
}

private fun createNodeSSLJKS(csrDef: CertGen.CSRDef, legalName: CordaX500Name, isOnNode: Boolean = false) {
    val partyName = Common.nameFromLegalName(legalName)
    val partyLabel = Common.nameFromLegalNameInLowerCase(legalName)
    val sourceStorepass = csrDef.storepass
    val sourceKeypass = csrDef.keypass
    val targetStorepass = inputParameter.keystorepass
    val targetKeypass = inputParameter.keystorepass
    val sourceAlias = csrDef.alias
    val targetAlias = Common.sslAliase

    val cerFile = Common.outputFile((inputParameter.cerFolder!!) / "cer", "${partyLabel}_tls.cer")
    val sourceJKSFile = Common.outputFile(inputParameter.csrFolder!!, "${partyLabel}_tls.jks")
    val targetJKSFile = if (isOnNode) Common.outputFile(inputParameter.outputFolder!!, "sslkeystore.jks") else Common.outputFile(inputParameter.outputFolder!!, "${partyName}/sslkeystore.jks")

    val sourceKetStore = loadOrCreateKeyStore(sourceJKSFile, sourceStorepass)
    val privateKey = sourceKetStore.getKey(sourceAlias, sourceKeypass.toCharArray())
    val targetKeyStore = loadOrCreateKeyStore(targetJKSFile, targetStorepass)

    val rootCert = X509Utilities.loadCertificateFromPEMFile(Common.outputFile(inputParameter.cerFolder!!, "rca.cer"))
    val issuingCA2Cert = X509Utilities.loadCertificateFromPEMFile(Common.outputFile(inputParameter.cerFolder!!, "ica1.cer"))
    val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)

    targetKeyStore.setKeyEntry(targetAlias, privateKey, targetKeypass.toCharArray(), arrayOf(cert, issuingCA2Cert, rootCert))

    targetKeyStore.save(targetJKSFile, targetStorepass)
}

private fun createNodeNodeJKS(csrDef: CertGen.CSRDef, legalName: CordaX500Name, isOnNode: Boolean = false) {
    val partyName = Common.nameFromLegalName(legalName)
    val partyLabel = Common.nameFromLegalNameInLowerCase(legalName)
    val sourceStorepass = csrDef.storepass
    val sourceKeypass = csrDef.keypass
    val targetStorepass = inputParameter.keystorepass
    val targetKeypass = inputParameter.keystorepass
    val sourceAlias = csrDef.alias
    val targetAlias_identity = Common.identityAlias
    val targetAlias_dummy = Common.dummyNodeAlias

    val cerFile_identity = Common.outputFile(inputParameter.cerFolder!! / "cer", "${partyLabel}_identity.cer")
    val cerFile_dummy = Common.outputFile(inputParameter.cerFolder!! / "cer", "${partyLabel}_dummyca.cer")
    val sourceJKSFile_identity = Common.outputFile(inputParameter.csrFolder!!, "${partyLabel}_identity.jks")
    val sourceJKSFile_dummy = Common.outputFile(inputParameter.csrFolder!!, "${partyLabel}_dummyca.jks")
    val targetJKSFile = if (isOnNode) Common.outputFile(inputParameter.outputFolder!!, "nodekeystore.jks") else Common.outputFile(inputParameter.outputFolder!!, "${partyName}/nodekeystore.jks")

    val sourceKetStore_identity = loadOrCreateKeyStore(sourceJKSFile_identity, sourceStorepass)
    val sourceKetStore_dummy = loadOrCreateKeyStore(sourceJKSFile_dummy, sourceStorepass)
    val privateKey_identity = sourceKetStore_identity.getKey(sourceAlias, sourceKeypass.toCharArray())
    val privateKey_dummy = sourceKetStore_dummy.getKey(sourceAlias, sourceKeypass.toCharArray())
    val targetKeyStore = loadOrCreateKeyStore(targetJKSFile, targetStorepass)

    val rootCert = X509Utilities.loadCertificateFromPEMFile(Common.outputFile(inputParameter.cerFolder!!, "rca.cer"))
    val issuingCA2Cert = X509Utilities.loadCertificateFromPEMFile(Common.outputFile(inputParameter.cerFolder!!, "ica1.cer"))
    val cert_identity = X509Utilities.loadCertificateFromPEMFile(cerFile_identity)
    val cert_dummy = X509Utilities.loadCertificateFromPEMFile(cerFile_dummy)

    targetKeyStore.setKeyEntry(targetAlias_dummy, privateKey_dummy, targetKeypass.toCharArray(), arrayOf(cert_dummy, issuingCA2Cert, rootCert))
    targetKeyStore.setKeyEntry(targetAlias_identity, privateKey_identity, targetKeypass.toCharArray(), arrayOf(cert_identity, issuingCA2Cert, rootCert))

    targetKeyStore.save(targetJKSFile, targetStorepass)
}

private fun createNetworkJKS(csrDef: CertGen.CSRDef, targetAlias: String) {
    val storepass = inputParameter.networkkeystorepass
    val keypass = inputParameter.networkkeystorepass
    val sourceAlias = csrDef.alias
    val legalName = if (targetAlias == "networkmap") csrDef.networkMap!! else csrDef.networkParameters!!
    val cerFile = Common.outputFile(inputParameter.cerFolder!! / "cer", Common.nameFromLegalNameInLowerCase(legalName) + ".cer")
    val sourceJKSFile = Common.outputFile(inputParameter.csrFolder!!, Common.jksFileNameFromLegalName(legalName))
    val targetJKSFile = Common.outputFile(inputParameter.outputFolder!!, Common.jksFileNameFromLegalName(legalName))

    val sourceKetStore = loadOrCreateKeyStore(sourceJKSFile, storepass)
    val privateKey = sourceKetStore.getKey(sourceAlias, keypass.toCharArray())
    val targetKeyStore = loadOrCreateKeyStore(targetJKSFile, storepass)

    val rootCert = X509Utilities.loadCertificateFromPEMFile(Common.outputFile(inputParameter.cerFolder!!, "rca.cer"))
    val issuingCA2Cert = X509Utilities.loadCertificateFromPEMFile(Common.outputFile(inputParameter.cerFolder!!, "ica2.cer"))
    val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)

    targetKeyStore.setKeyEntry(targetAlias, privateKey, keypass.toCharArray(), arrayOf(cert, issuingCA2Cert, rootCert))

    targetKeyStore.save(targetJKSFile, storepass)
}
