package ch.ge.thhofer.ctf.crypto

import com.google.common.base.Stopwatch
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Security
import java.util.concurrent.TimeUnit
import javax.xml.bind.DatatypeConverter

val p = BigInteger("14219462995139870823732990991847116988782830807352488252401693038616204860083820490505711585808733926271164036927426970740721056798703931112968394409581", 10)
val g = BigInteger("13281265858694166072477793650892572448879887611901579408464846556561213586303026512968250994625746699137042521035053480634512936761634852301612870164047", 10)
val keyLength = 32
val two: BigInteger = BigInteger.valueOf(2L)
val ths: BigInteger = p.subtract(BigInteger.ONE).divide(two)

fun main(args: Array<String>) {
    Security.addProvider(BouncyCastleProvider())
    val keyFactory = KeyFactory.getInstance("ECDSA", "BC")

    val stopwatch = Stopwatch.createStarted()
    println("Getting started")

    println("Creating CyclicGroup")
    val group = CyclicGroup(p, g)
    println("Initialized in ${stopwatch.elapsed(TimeUnit.MILLISECONDS)} ms")

    stopwatch.reset().start()
    println("Loading the public key")
    val publicKeyParser = PublicKeyParser(keyFactory, ECNamedCurveTable.getParameterSpec("secp256r1"))
    val publicKey = parsePublicKey(publicKeyParser)
    println("Key loaded in ${stopwatch.elapsed(TimeUnit.MILLISECONDS)}ms")

    stopwatch.reset().start()
    println("Computing members")
    val members = group.members()
    println("Found ${members.size} members in ${stopwatch.elapsed(TimeUnit.MILLISECONDS)}ms")

    stopwatch.reset().start()
    println("Computing private keys")
    val possibleKeys = computeKeys(members)
    println("Computed ${possibleKeys.size} possible private keys in ${stopwatch.elapsed(TimeUnit.MILLISECONDS)}ms")

    stopwatch.reset().start()
    println("Looking for private key matching the public key")
    val privateKey = possibleKeys
            .map { toPrivateKey(it) }
            .find { correspondingPublicKey(keyFactory, it) == publicKey }

    if (privateKey != null) {
        println("Success, the private key is $privateKey")
        println("Found matching private key in ${stopwatch.elapsed(TimeUnit.MILLISECONDS)}ms")
    } else {
        println("Failed to compute private key")
    }

}

fun computeKeys(startingStates: Set<BigInteger>): Set<BigInteger> =
        startingStates.map { computeKey(it) }.toSet()

fun computeKey(startingState: BigInteger): BigInteger {
    var x = startingState
    var ret = BigInteger.ZERO
    for (i in 0..(keyLength * 8 - 1)) {
        x = g.modPow(x, p)
        if (x > ths) {
            ret = ret.add(two.pow(i))
        }
    }
    return ret
}

fun toPrivateKey(secret: BigInteger): ECPrivateKey {
    val parameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
    val keySpec = ECPrivateKeySpec(secret, parameterSpec)
    return BCECPrivateKey("ECDSA", keySpec, BouncyCastleProvider.CONFIGURATION)
}

fun parsePublicKey(publicKeyParser: PublicKeyParser): PublicKey {
    val inputStream = ClassLoader.getSystemClassLoader().getResourceAsStream("id_ecdsa.pub")
    val line = BufferedReader(InputStreamReader(inputStream)).readLine()
    println("read line $line")
    val base64EncodedKey = line.split(" ").first { it.startsWith("AAAA") }
    return publicKeyParser.parse(ByteArrayInputStream(DatatypeConverter.parseBase64Binary(base64EncodedKey)))
}

fun correspondingPublicKey(keyFactory: KeyFactory, privateKey: ECPrivateKey): PublicKey {
    val ecParameterSpec = privateKey.parameters

    val q = ecParameterSpec.g.multiply(privateKey.d)
    val publicDerBytes = q.getEncoded(false)
    val point = ecParameterSpec.curve.decodePoint(publicDerBytes)
    val ecPublicKeySpec = ECPublicKeySpec(point, ecParameterSpec)
    return keyFactory.generatePublic(ecPublicKeySpec)
}