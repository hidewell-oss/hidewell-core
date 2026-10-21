package com.sentrybrain.hidewell.core

import java.io.File
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/** Software oracle for host tests ONLY (never ship). */
class SoftwareOracle : HardwareOracle {
    private val key = ByteArray(32) { 7 }

    override fun securityLevel() = SecurityLevel.SOFTWARE_MOCK

    override fun clockSample() = JvmTestClock.sample()

    override fun chainStep(input: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(input) }

    override fun sealDeviceSecret(secret: ByteArray): ByteArray {
        val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        return iv + c.doFinal(secret)
    }

    override fun openDeviceSecret(sealed: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, sealed, 0, 12))
        return c.doFinal(sealed, 12, sealed.size - 12)
    }
}

private object JvmTestClock {
    private val epoch = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
    private val started = System.nanoTime()
    fun sample() = ClockSample(epoch.copyOf(), ((System.nanoTime() - started) / 1_000_000).toULong())
}

class BindingsTest {
    private val geometry = Geometry(
        chunkSize = 65_536u, blockSize = 4096u, segmentBlocks = 4u,
        buckets = listOf(64uL * 65_536uL, 128uL * 65_536uL), coverChunksPerCommit = 2u,
        fillerPermilleMin = 50u, fillerPermilleMax = 150u, fillerSlotsMin = 1u, fillerSlotsMax = 8u,
    )
    private val params = KdfParams(chainSteps = 4u, argonMKib = 65_536u, argonT = 1u, argonP = 1u)
    private val pattern = listOf(byteArrayOf(7, 0, 11, 22, 13, 4, 8, 15, 21))

    @Test
    fun createUnlockImportRead() {
        val file = File.createTempFile("hidewell", ".bin").also { it.delete() }
        try {
            val oracle = SoftwareOracle()
            val words = generatePhrase()
            val created = createDevice(file.path, oracle, geometry, params, words, pattern)
            val body = ByteArray(50_000) { (it * 31).toByte() }
            val meta = NewItem("IMG_0001.HEIC", "image/heic", 1, 2, listOf(), listOf())
            val id = created.vault.import(meta, body, null)
            created.vault.lock()
            val device = Device.open(file.path, oracle, geometry, created.sealedDeviceSecret)
            try {
                device.unlock(listOf(byteArrayOf(0, 6, 12, 18, 24, 23, 17)))
                throw AssertionError("wrong pattern accepted")
            } catch (e: HidewellException.WrongPattern) {
                // Expected
            }
            val vault = device.unlock(pattern)
            assertEquals(1uL, vault.itemCount())
            assertArrayEquals(body, vault.read(id, 0uL, body.size.toULong()))
            // Unsized import + extra; counters.
            val w = vault.beginImportUnsized(NewItem("clip.mp4", "video/mp4", 1, 2, listOf(), listOf(), "pair:1".toByteArray()))
            w.write(body.copyOfRange(0, 20_000))
            w.write(body.copyOfRange(20_000, body.size))
            val id2 = w.finish(null)
            assertEquals(body.size.toULong(), vault.item(id2).size)
            assertArrayEquals("pair:1".toByteArray(), vault.item(id2).extra)
            vault.setItemExtra(id, byteArrayOf(1))
            assertArrayEquals(byteArrayOf(1), vault.item(id).extra)
            assertEquals(0u, vault.wipeAfter())
            assertEquals(0uL, device.retryAfterSeconds())
            // A sub-policy stroke is rejected without counting.
            val failed = device.failedAttempts()
            try {
                device.unlock(listOf(byteArrayOf(0, 1, 2)))
                throw AssertionError("short pattern accepted")
            } catch (e: HidewellException.InvalidPattern) {
                // Expected
            }
            assertEquals(failed, device.failedAttempts())
            // Phrase check, blocked shape names, thumbnail backfill.
            assertEquals(true, device.verifyPhrase(words))
            assertEquals(false, device.verifyPhrase(generatePhrase()))
            assertEquals(BlockedShape.Z_SHAPE, patternStrength(listOf(byteArrayOf(0, 4, 20, 24))).blockedShape)
            vault.setThumbnail(id2, byteArrayOf(7, 7, 7))
            assertArrayEquals(byteArrayOf(7, 7, 7), vault.thumbnail(id2))
            // In-place content replacement.
            vault.replaceContent(id2, "edited".toByteArray(), 42L)
            assertArrayEquals("edited".toByteArray(), vault.read(id2, 0uL, 100uL))
            assertEquals(6uL, vault.item(id2).size)
            assertEquals(42L, vault.item(id2).modified)
            assertArrayEquals(byteArrayOf(7, 7, 7), vault.thumbnail(id2))
            try {
                vault.replaceContent(999uL, byteArrayOf(1), 0L)
                throw AssertionError("replaced a missing item")
            } catch (e: HidewellException.NotFound) {
                // Expected
            }
            // Protection info.
            val info = device.protectionInfo()
            assertEquals(SecurityLevel.SOFTWARE_MOCK, info.securityLevel)
            assertEquals(true, info.chainSteps > 0u)
            assertEquals(null, info.estimatedAttemptMillis)
            // Vault names.
            vault.setName("  Main  ")
            assertEquals("Main", vault.name())
            try {
                vault.setName("é".repeat(65))
                throw AssertionError("over-long name accepted")
            } catch (e: HidewellException.InvalidArgument) {
                // Expected
            }
            assertEquals(listOf<DecoyInfo>(), vault.decoys())
            // Phrase recovery without cloud; erase.
            val found = device.recoverWithPhrase(words)
            assertEquals(1, found.size)
            val newPattern = listOf(byteArrayOf(12, 1, 10, 23, 14, 3, 6, 19))
            device.resetPatternWithPhrase(words, found[0].index, newPattern)
            assertEquals(2uL, device.unlock(newPattern).itemCount())
            device.erase()
            try {
                device.unlock(newPattern)
                throw AssertionError("erased device unlocked")
            } catch (e: HidewellException.Locked) {
                // Expected
            }
        } finally {
            file.delete()
        }
    }
}
