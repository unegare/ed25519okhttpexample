package com.example.ed25519okhttpexample

import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.TlsVersion
import okhttp3.tls.HandshakeCertificates
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider
import org.bouncycastle.util.encoders.Base64
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Collections
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager


const val BASE_SRV_URL: String  = "127.0.0.1:3005"

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

//    val certificates = HandshakeCertificates.Builder()
//        .addTrustedCertificate(caCertificate)
//        .build()

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

    val certificatePinner = CertificatePinner.Builder()
//        .add("example.com", "sha256/ssJ4JcD7aA/aqPUnlvmESHEjtBLWg0ShqZ670RGU36c=") // IS NOT CHECKED
        .add(BASE_SRV_URL.split(":").first(), "sha256/ssJ4JcD7aA/aqPUnlvmESHEjtBLWg0ShqZ670RGU36c=") // CHECKED, but after HostnameVerifier
        .build()

    val tls13Spec = ConnectionSpec.Builder(ConnectionSpec.Companion.MODERN_TLS)
        .tlsVersions(TlsVersion.TLS_1_3)
        .build()

    return OkHttpClient.Builder()
//        .sslSocketFactory(sslContext.socketFactory, certificates.trustManager)
        .sslSocketFactory(sslContext.socketFactory, trustManager)
        .hostnameVerifier({hostname, session ->
            hostname.equals(BASE_SRV_URL.split(":").first()) && getSessionSha256Base64(session) == "ssJ4JcD7aA/aqPUnlvmESHEjtBLWg0ShqZ670RGU36c="
        })
        .connectionSpecs(Collections.singletonList(tls13Spec))
        .certificatePinner(certificatePinner)
        .build()
}

fun getSessionSha256Base64(session: SSLSession): String? {
    return try {
        val certificates = session.peerCertificates
        val leafCert = certificates[0] as? X509Certificate ?: return null
        val spki = leafCert.publicKey.encoded
        val digest = MessageDigest.getInstance("SHA-256")
        val hashedBytes = digest.digest(spki)
        val res = Base64.toBase64String(hashedBytes)
        println(res)
        res
    } catch (e: Exception) {
        e.printStackTrace()
        null
    }
}