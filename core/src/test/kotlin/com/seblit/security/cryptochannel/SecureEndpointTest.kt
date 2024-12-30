package com.seblit.security.cryptochannel

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import java.security.MessageDigest
import java.security.SecureRandom

class SecureEndpointTest {

    private lateinit var secureEndpoint: TestEndpoint

    private lateinit var spyRandom: SecureRandom
    private lateinit var secretSalt: ByteArray

    @BeforeEach
    fun setup() {
        secretSalt = ByteArray(256).apply { SecureRandom().nextBytes(this) }
        spyRandom = spy()
        secureEndpoint = TestEndpoint(spyRandom, secretSalt)
    }

    @Test
    fun testNewKeypair() {
        secureEndpoint.testNewKeypair()
    }

    @Test
    fun testGenerateIv() {
        secureEndpoint.testGenerateIv()
    }

    @Test
    fun testHash() {
        secureEndpoint.testHash()
    }

    @Test
    fun testDeriveAesKey() {
        secureEndpoint.testDeriveAesKey()
    }

    @Test
    fun testEncryption() {
        secureEndpoint.testEncryption()
    }

    private class TestEndpoint(
        private val spyRandom: SecureRandom,
        private val secretSalt: ByteArray
    ) : SecureEndpoint(random = spyRandom) {

        fun testNewKeypair() {
            val keys = newKeypair()
            assertNotNull(keys)
            assertEquals("EC", keys.private.algorithm)
            assertEquals("EC", keys.public.algorithm)
        }

        fun testGenerateIv() {
            val generatedIv = generateBytes(ivLength)
            assertEquals(DEFAULT_IV_LENGTH, generatedIv.size)
            verify(spyRandom).nextBytes(generatedIv)
        }

        fun testHash() {
            val data = ByteArray(100).apply { spyRandom.nextBytes(this) }
            val hash = MessageDigest.getInstance("SHA-256").digest(data)
            val result = hash(data)
            assertArrayEquals(hash, result)
        }

        fun testDeriveAesKey() {
            val keyPair = newKeypair()
            val aesKey = deriveAesKey(keyPair.private, keyPair.public, secretSalt)
            assertEquals(32, aesKey.size)
            assertTrue(aesKey.any { data -> data != 0.toByte() })
        }

        fun testEncryption() {
            val data = ByteArray(10).apply { spyRandom.nextBytes(this) }
            val iv = ByteArray(DEFAULT_IV_LENGTH).apply { spyRandom.nextBytes(this) }
            val aesKey = ByteArray(32).apply { spyRandom.nextBytes(this) }

            val encCipher = createCipher(false, DEFAULT_TAG_LENGTH, iv, aesKey)
            val decCipher = createCipher(true, DEFAULT_TAG_LENGTH, iv, aesKey)

            val encData = encCipher.doFinal(data)
            val result = decCipher.doFinal(encData)

            assertArrayEquals(data, result)
        }
    }

}