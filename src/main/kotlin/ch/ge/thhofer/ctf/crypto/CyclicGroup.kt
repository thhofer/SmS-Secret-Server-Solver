package ch.ge.thhofer.ctf.crypto

import java.math.BigInteger
import java.util.*

class CyclicGroup(val p: BigInteger, val g: BigInteger) {
    fun members(): Set<BigInteger> {
        val valuesFound: MutableSet<BigInteger> = HashSet()
        var member: BigInteger

        member = g
        while (!valuesFound.contains(member)) {
            valuesFound.add(member)
            member = member.multiply(g).mod(p)
        }

        return valuesFound
    }
}