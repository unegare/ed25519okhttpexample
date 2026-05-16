package com.example.ed25519okhttpexample

import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

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

    val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
    trustStore.load(null, null)
    trustStore.setCertificateEntry("ca", caCertificate)

    val tmf = TrustManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME)
    tmf.init(trustStore)
    val trustManager = tmf.trustManagers
        .filterIsInstance<X509TrustManager>()
        .single()

    if (trustManager == null) {
        println("trustManager is NULL")
    }


    val sslContext = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME)
//    sslContext.init(kmf.keyManagers, arrayOf(certificates.trustManager), SecureRandom())
    sslContext.init(kmf.keyManagers, arrayOf(trustManager), SecureRandom())

    return OkHttpClient.Builder()
//        .sslSocketFactory(sslContext.socketFactory, certificates.trustManager)
        .sslSocketFactory(sslContext.socketFactory, trustManager)
        .build()
}