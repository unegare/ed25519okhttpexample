package com.example.ed25519okhttpexample

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.example.ed25519okhttpexample.ui.theme.Ed25519OkHttpExampleTheme
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Request
import okhttp3.Response
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider
import org.bouncycastle.openssl.PEMParser
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
        Security.addProvider(BouncyCastleJsseProvider())
        enableEdgeToEdge()
        setContent {
            Ed25519OkHttpExampleTheme {
                Surface {
                    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                        Column {
                            Button({
                                CoroutineScope(Dispatchers.Default).launch {
                                    val kp = generateEd25519Keys()
                                    val (pub, priv) = convertToPublicPrivateKey(kp)
                                    val cert = generateX509Certificate2(
                                        X500Name("CN=issuer"),
                                        X500Name("CN=subject"),
                                        kp
                                    )
                                    val srvcert = loadCertificate(applicationContext, R.raw.srvcert)
                                        ?: throw IllegalArgumentException("srvcert cannot be null")

                                    val client = createMtlsClient(priv, cert, srvcert)
                                    val request = Request.Builder()
                                        .url("https://127.0.0.1:3005")
                                        .build()

                                    val data = withContext(Dispatchers.IO) {
                                        suspendCancellableCoroutine { continuation ->
                                            val call = client.newCall(request)

                                            continuation.invokeOnCancellation {
                                                call.cancel()
                                            }

                                            call.enqueue(object : Callback {
                                                override fun onFailure(call: Call, e: IOException) {
                                                    continuation.resumeWithException(e)
                                                }

                                                override fun onResponse(
                                                    call: Call,
                                                    response: Response
                                                ) {
                                                    response.use {
                                                        if (!response.isSuccessful) {
                                                            continuation.resumeWithException(
                                                                IOException(
                                                                    "Unexpected code $response"
                                                                )
                                                            )
                                                        } else {
                                                            continuation.resume(
                                                                response.body?.string() ?: ""
                                                            )
                                                        }
                                                    }
                                                }
                                            })
                                        }
                                    }
                                    println(data)
                                }
                            }) {
                                Text("kick off")
                            }
                            Button({
                                val kp = generateEd25519Keys()
                                val (pub, priv) = convertToPublicPrivateKey(kp)
                                val data = ByteArray(200, { it.toByte() })
                                val signature = signWithEd25519(priv, data)
                                println("signature ed25519: ${signature}")
                                val verdict = verifyEd25519Signature(pub, data, signature)
                                println("verdict: ${verdict}")
                            }) {
                                Text("sign")
                            }
                        }
                    }
                }
            }
        }
    }
}

fun loadCertificate(context: Context, resId: Int): X509Certificate? {
    context.resources.openRawResource(resId).use { inputStream ->
        InputStreamReader(inputStream).use { reader ->
            PEMParser(reader).use { pemParser ->
                val pemObject = pemParser.readObject()
                if (pemObject is X509CertificateHolder) {
                    return JcaX509CertificateConverter()
                        .setProvider("BC")
                        .getCertificate(pemObject)
                }
            }
        }
    }
    return null
}