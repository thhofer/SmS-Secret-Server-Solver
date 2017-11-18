package ch.ge.thhofer.ctf.crypto

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.io.InputStream
import java.math.BigInteger
import java.security.KeyFactory
import javax.xml.bind.DatatypeConverter

class PublicKeyParser(val keyFactory: KeyFactory, val parameterSpec: ECNamedCurveParameterSpec) {
    fun parse(inputStream: InputStream): BCECPublicKey {
        val type = readString(inputStream)
        println("found type $type")
        if (type == "ecdsa-sha2-nistp256") {
            val identifier = readString(inputStream)
            println("found identifier $identifier")
            if (!type.endsWith(identifier)) {
                throw IllegalArgumentException("invalid identifier $identifier for type $type")
            }

            val q = readBigIng(inputStream)
            println("found q = $q")

            return getKeyBC(q)
        } else {
            throw IllegalArgumentException("Unsupported type $type")
        }
    }

    private fun getKeyBC(q: BigInteger): BCECPublicKey {
        val ecPoint = parameterSpec.curve.decodePoint(q.toByteArray())
        val keySpec = ECPublicKeySpec(ecPoint, parameterSpec)
        return keyFactory.generatePublic(keySpec) as BCECPublicKey
    }


    private fun readString(inputStream: InputStream): String {
        val length = readLength(inputStream)
        val byteArray = ByteArray(length, { inputStream.read().toByte() })
        return String(byteArray)
    }

    private fun readLength(inputStream: InputStream): Int {
        val bytes = ByteArray(4, { inputStream.read().toByte() })
        println("Bytes read: ${DatatypeConverter.printHexBinary(bytes)}")
        val intLength = BigInteger(bytes).intValueExact()
        println("found int length $intLength")
        return intLength
    }

    private fun readBigIng(inputStream: InputStream): BigInteger {
        val length = readLength(inputStream)
        val byteArray = ByteArray(length, { inputStream.read().toByte() })
        return BigInteger(byteArray)
    }
}