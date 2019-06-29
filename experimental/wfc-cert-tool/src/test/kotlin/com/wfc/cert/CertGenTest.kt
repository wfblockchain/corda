package com.wfc.cert

import net.corda.core.internal.div
import net.corda.nodeapi.internal.crypto.X509Utilities
import net.corda.nodeapi.internal.crypto.loadOrCreateKeyStore
import net.corda.nodeapi.internal.crypto.save
import org.junit.Test
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.assertNotNull

/**
 * Per README.md of Experimental project, unit tests are disabled.
 * So, we do it in node-api test WFC_CertGenTest.kt
 * Or,
 * gradlew test -Dexperimental.test.enable
 * In Intellij run configuration, add -Dexperimental.test.enable to VM option for each test.
 *
 */
class CertGenTest {

    private val caCerFolder = Paths.get(System.getProperty("user.home")) / "certs/wfc/dev/cer_20190622"
    private val cerFolder = caCerFolder / "cer"
    private val csrFolder = Paths.get(System.getProperty("user.home")) / "certs/wfc/dev/csrs_20190622"
    private fun caCerFile(name: String): Path = caCerFolder / name
    private fun cerFile(name: String): Path = cerFolder / name
    private fun csrFile(name: String): Path = csrFolder / name

    @Test
    fun `load a ca cer file certificate`() {
        val file = caCerFile("rca.cer")
        val readCertificate = X509Utilities.loadCertificateFromPEMFile(file)
    }

    @Test
    fun `truststore`() {
        val cerFile = caCerFile("rca.cer")
        val jksFile = caCerFile("truststore.jks")
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)
        val keyStore = loadOrCreateKeyStore(jksFile, "trustpass")
        keyStore.setCertificateEntry("cordarootca", cert)
//        keyStore.deleteEntry("abc")
        keyStore.save(jksFile, "trustpass")

        val reloadedKeystore = loadOrCreateKeyStore(jksFile, "trustpass")
        val reloadedPublicKey = reloadedKeystore.getCertificate("cordarootca").publicKey

        assertNotNull(reloadedPublicKey)
    }

    @Test
    fun `networkmap`() {
        val storepass = "trustpass"
        val keypass = "trustpass"
        val sourceAlias = "csr"
        val targetAlias = "networkmap"

        val cerFile = cerFile("networkmap.cer")
        val sourceJKSFile = csrFile("networkmap.jks")
        val targetJKSFile = caCerFile("networkmap.jks")

        val sourceKetStore = loadOrCreateKeyStore(sourceJKSFile, storepass)
        val privateKey = sourceKetStore.getKey(sourceAlias, keypass.toCharArray())
        val targetKeyStore = loadOrCreateKeyStore(targetJKSFile, storepass)

        val rootCert = X509Utilities.loadCertificateFromPEMFile(caCerFile("rca.cer"))
        val issuingCA2Cert = X509Utilities.loadCertificateFromPEMFile(caCerFile("ica2.cer"))
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)

        targetKeyStore.setKeyEntry(targetAlias, privateKey, keypass.toCharArray(), arrayOf(cert, issuingCA2Cert, rootCert))

        targetKeyStore.save(targetJKSFile, storepass)

    }

    @Test
    fun `networkparameters`() {
        val storepass = "trustpass"
        val keypass = "trustpass"
        val sourceAlias = "csr"
        val targetAlias = "networkparameters"

        val cerFile = cerFile("networkparameters.cer")
        val sourceJKSFile = csrFile("networkparameters.jks")
        val targetJKSFile = caCerFile("networkparameters.jks")

        val sourceKetStore = loadOrCreateKeyStore(sourceJKSFile, storepass)
        val privateKey = sourceKetStore.getKey(sourceAlias, keypass.toCharArray())
        val targetKeyStore = loadOrCreateKeyStore(targetJKSFile, storepass)

        val rootCert = X509Utilities.loadCertificateFromPEMFile(caCerFile("rca.cer"))
        val issuingCA2Cert = X509Utilities.loadCertificateFromPEMFile(caCerFile("ica2.cer"))
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)

        targetKeyStore.setKeyEntry(targetAlias, privateKey, keypass.toCharArray(), arrayOf(cert, issuingCA2Cert, rootCert))

        targetKeyStore.save(targetJKSFile, storepass)

    }

    @Test
    fun `ssl`() {
//        val party = "notaryha"
        val party = "partya"
        val sourceStorepass = "trustpass"
        val sourceKeypass = "trustpass"
        val targetStorepass = "cordacadevpass"
        val targetKeypass = "cordacadevpass"
        val sourceAlias = "csr"
        val targetAlias = "cordaclienttls"

        val cerFile = cerFile("${party}_tls.cer")
        val sourceJKSFile = csrFile("${party}_tls.jks")
        val targetJKSFile = caCerFile("${party}/sslkeystore.jks")

        val sourceKetStore = loadOrCreateKeyStore(sourceJKSFile, sourceStorepass)
        val privateKey = sourceKetStore.getKey(sourceAlias, sourceKeypass.toCharArray())
        val targetKeyStore = loadOrCreateKeyStore(targetJKSFile, targetStorepass)

        val rootCert = X509Utilities.loadCertificateFromPEMFile(caCerFile("rca.cer"))
        val issuingCA2Cert = X509Utilities.loadCertificateFromPEMFile(caCerFile("ica1.cer"))
        val cert = X509Utilities.loadCertificateFromPEMFile(cerFile)

        targetKeyStore.setKeyEntry(targetAlias, privateKey, targetKeypass.toCharArray(), arrayOf(cert, issuingCA2Cert, rootCert))

        targetKeyStore.save(targetJKSFile, targetStorepass)

    }

    @Test
    fun `node`() {
//        val party = "notaryha"
        val party = "partya"
        val sourceStorepass = "trustpass"
        val sourceKeypass = "trustpass"
        val targetStorepass = "cordacadevpass"
        val targetKeypass = "cordacadevpass"
        val sourceAlias = "csr"
        val targetAlias_identity = "identity-private-key"
        val targetAlias_dummy = "cordaclientca"

        val cerFile_identity = cerFile("${party}_identity.cer")
        val cerFile_dummy = cerFile("${party}_dummyca.cer")
        val sourceJKSFile_identity = csrFile("${party}_identity.jks")
        val sourceJKSFile_dummy = csrFile("${party}_dummyca.jks")
        val targetJKSFile = caCerFile("${party}/nodekeystore.jks")

        val sourceKetStore_identity = loadOrCreateKeyStore(sourceJKSFile_identity, sourceStorepass)
        val sourceKetStore_dummy = loadOrCreateKeyStore(sourceJKSFile_dummy, sourceStorepass)
        val privateKey_identity = sourceKetStore_identity.getKey(sourceAlias, sourceKeypass.toCharArray())
        val privateKey_dummy = sourceKetStore_dummy.getKey(sourceAlias, sourceKeypass.toCharArray())
        val targetKeyStore = loadOrCreateKeyStore(targetJKSFile, targetStorepass)

        val rootCert = X509Utilities.loadCertificateFromPEMFile(caCerFile("rca.cer"))
        val issuingCA2Cert = X509Utilities.loadCertificateFromPEMFile(caCerFile("ica1.cer"))
        val cert_identity = X509Utilities.loadCertificateFromPEMFile(cerFile_identity)
        val cert_dummy = X509Utilities.loadCertificateFromPEMFile(cerFile_dummy)

        targetKeyStore.setKeyEntry(targetAlias_dummy, privateKey_dummy, targetKeypass.toCharArray(), arrayOf(cert_dummy, issuingCA2Cert, rootCert))
        targetKeyStore.setKeyEntry(targetAlias_identity, privateKey_identity, targetKeypass.toCharArray(), arrayOf(cert_identity, issuingCA2Cert, rootCert))

        targetKeyStore.save(targetJKSFile, targetStorepass)

    }

    @Test
    fun `load a cer file certificate`() {
        val file = cerFile("partya_identity.cer")
        val readCertificate = X509Utilities.loadCertificateFromPEMFile(file)
    }

}