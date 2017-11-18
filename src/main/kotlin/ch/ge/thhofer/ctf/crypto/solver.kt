package ch.ge.thhofer.ctf.crypto

import com.google.common.base.Stopwatch
import java.math.BigInteger
import java.util.concurrent.TimeUnit

val p = BigInteger("14219462995139870823732990991847116988782830807352488252401693038616204860083820490505711585808733926271164036927426970740721056798703931112968394409581", 10)
val g = BigInteger("13281265858694166072477793650892572448879887611901579408464846556561213586303026512968250994625746699137042521035053480634512936761634852301612870164047", 10)
val keyLength = 32
val two: BigInteger = BigInteger.valueOf(2L)
val ths: BigInteger = p.subtract(BigInteger.ONE).divide(two)

fun main (args: Array<String>) {
    val stopwatch = Stopwatch.createStarted()
    println("Getting started")

    println("Creating CyclicGroup")
    val group = CyclicGroup(p, g)
    println("Initialized in ${stopwatch.elapsed(TimeUnit.MILLISECONDS)} ms")

    stopwatch.reset().start()
    println("Computing members")
    val members = group.members()
    println("Found ${members.size} members in ${stopwatch.elapsed(TimeUnit.MILLISECONDS)}ms")

    stopwatch.reset().start()
    println("Computing keys")
    val possibleKeys = computeKeys(members)
    println("Computed ${possibleKeys.size} possibles keys in ${stopwatch.elapsed(TimeUnit.MILLISECONDS)}ms")
}

fun computeKeys(startingStates: Set<BigInteger>): Set<BigInteger> = startingStates.map { computeKey(it) }.toSet()

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