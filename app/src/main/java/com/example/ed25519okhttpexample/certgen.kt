package com.example.ed25519okhttpexample

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Date

fun generateEd25519Keys(): AsymmetricCipherKeyPair {
    val random = SecureRandom()
    val keyGen = Ed25519KeyPairGenerator()
    keyGen.init(Ed25519KeyGenerationParameters(random))
    return keyGen.generateKeyPair()
}

fun convertToPublicPrivateKey(kp: AsymmetricCipherKeyPair): Pair<PublicKey, PrivateKey> {
    val privateKeyParams = kp.private as Ed25519PrivateKeyParameters
    val publicKeyParams = kp.public as Ed25519PublicKeyParameters

    val privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(
        privateKeyParams
    )
    val pkcs8Spec = PKCS8EncodedKeySpec(privateKeyInfo.encoded)

    val subjectPublicKeyInfo = SubjectPublicKeyInfo(
        AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
        publicKeyParams.encoded
    )
    val x509EncodedKeySpec = X509EncodedKeySpec(subjectPublicKeyInfo.encoded)

    val kf = KeyFactory.getInstance("Ed25519", "BC")

    val jcaPrivateKey: PrivateKey =
    return Pair(
        kf.generatePublic(x509EncodedKeySpec),
        kf.generatePrivate(pkcs8Spec)
    )
}

fun generateX509Certificate2(issuer: X500Name, subject: X500Name, kp: AsymmetricCipherKeyPair): X509Certificate {
    val serialNumber = BigInteger(64, SecureRandom())
    val startDate = Date()
    val endDate = Date(startDate.time + 365L * 24 * 60 * 60 * 1000) // 1 year

    val (pub, priv) = convertToPublicPrivateKey(kp)

    val certBuilder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
        issuer,
        serialNumber,
        startDate,
        endDate,
        subject,
        pub
    )

    val signer: ContentSigner = JcaContentSignerBuilder("Ed25519")
        .setProvider("BC")
        .build(priv)

    val certHolder = certBuilder.build(signer)

    val x509Certificate: X509Certificate = JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(certHolder)
    return x509Certificate
}

fun signWithEd25519(privateKey: PrivateKey, data: ByteArray): ByteArray {
    return Signature.getInstance("Ed25519", "BC").run {
        initSign(privateKey)
        update(data)
        sign()
    }
}

fun verifyEd25519Signature(publicKey: PublicKey, originalData: ByteArray, signatureBytes: ByteArray): Boolean {
    return try {
        Signature.getInstance("Ed25519", "BC").run{
            initVerify(publicKey)
            update(originalData)
            verify(signatureBytes)
        }
    } catch (e: Exception) {
        false
    }
}