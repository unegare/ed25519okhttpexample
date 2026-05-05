package com.example.ed25519okhttpexample

import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

fun createMtlsClient(
    clientPrivateKey: PrivateKey,
    clientCertificate: X509Certificate,
    caCertificate: X509Certificate
): OkHttpClient {

    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
    keyStore.load(null, null)
    keyStore.setKeyEntry(
        "client-key",
        clientPrivateKey,
        "password".toCharArray(),
        arrayOf(clientCertificate)
    )

    val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
    kmf.init(keyStore, "password".toCharArray())

    val certificates = HandshakeCertificates.Builder()
        .addTrustedCertificate(caCertificate)
        .build()

    val sslContext = SSLContext.getInstance("TLSv1.3")
    sslContext.init(kmf.keyManagers, arrayOf(certificates.trustManager), SecureRandom())

    return OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, certificates.trustManager)
        .build()
}