package com.seblit.security.cryptochannel

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class SecureClientTest {

    companion object {

        private const val AES_ALGORITHM = "AES"
        private lateinit var SERVER_KEYS: KeyPair
        private lateinit var SERVER_IV: ByteArray
        private lateinit var SERVER_SALT: ByteArray
        private lateinit var SESSION_ID : ByteArray
        private lateinit var DATA: ByteArray

        @JvmStatic
        @BeforeAll
        fun setupTest() {
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec(SecureEndpoint.DEFAULT_CURVE))
            SERVER_KEYS = generator.generateKeyPair()
            val random = SecureRandom()
            SERVER_IV = ByteArray(SecureEndpoint.DEFAULT_IV_LENGTH).apply { random.nextBytes(this) }
            SERVER_SALT = ByteArray(256).apply { random.nextBytes(this) }
            SESSION_ID = ByteArray(10).apply { random.nextBytes(this) }
            DATA = ByteArray(10).apply { random.nextBytes(this) }
        }
    }

    private lateinit var client: SecureClient
    private lateinit var currentClientKey: PublicKey

    @BeforeEach
    fun setup() {
        client = SecureClient()
    }

    @Test
    fun testDecryptDownload() {
        val result = client.decryptDownload { pubKey ->
            val encData = deriveServerAes(pubKey, false, SERVER_IV, SecureEndpoint.DEFAULT_TAG_LENGTH).doFinal(DATA)
            SecureEndpoint.DownloadResponse(
                SERVER_IV, SecureEndpoint.DEFAULT_TAG_LENGTH, SERVER_KEYS.public,
                SERVER_SALT, encData
            )
        }
        assertArrayEquals(DATA, result)
    }

    @Test
    fun testDecryptDownstream() {
        val resultStream = client.decryptDownstream { pubKey ->
            val encData = deriveServerAes(pubKey, false, SERVER_IV, SecureEndpoint.DEFAULT_TAG_LENGTH).doFinal(DATA)
            SecureEndpoint.DownloadResponse(
                SERVER_IV, SecureEndpoint.DEFAULT_TAG_LENGTH, SERVER_KEYS.public,
                SERVER_SALT, ByteArrayInputStream(encData)
            )
        }
        val transformer = ByteArrayOutputStream()
        resultStream.use { it.transferTo(transformer) }
        transformer.use { assertArrayEquals(DATA, it.toByteArray()) }
    }

    @Test
    fun testEncryptUpload() {
        client.encryptUpload(DATA, { pubKey ->
            currentClientKey = pubKey
            SecureEndpoint.UploadInitResponse(SERVER_KEYS.public, SERVER_SALT, SESSION_ID)
        }, { request, encryptedData ->
            assertArrayEquals(SESSION_ID, request.sessionId)
            val decryptedData =
                deriveServerAes(currentClientKey, true, request.iv, request.tagLength).doFinal(encryptedData)
            assertArrayEquals(DATA, decryptedData)
        })
    }

    @Test
    fun testEncryptUpstream() {
        val targetStream = ByteArrayOutputStream()
        lateinit var receivedRequest: SecureEndpoint.UploadRequest<ByteArray>
        client.encryptUpstream({ pubKey ->
            currentClientKey = pubKey
            SecureEndpoint.UploadInitResponse(SERVER_KEYS.public, SERVER_SALT, SESSION_ID)
        }, { uploadRequest ->
            receivedRequest = uploadRequest
            targetStream
        }).use { it.write(DATA) }
        assertArrayEquals(SESSION_ID, receivedRequest.sessionId)
        val decryptedData = deriveServerAes(
            currentClientKey,
            true,
            receivedRequest.iv,
            receivedRequest.tagLength
        ).doFinal(targetStream.use { it.toByteArray() })
        assertArrayEquals(DATA, decryptedData)
    }

    private fun deriveServerAes(clientKey: PublicKey, isDecrypt: Boolean, iv: ByteArray, tagLength: Int): Cipher {
        val agreement = KeyAgreement.getInstance(SecureEndpoint.KEY_AGREEMENT)
        agreement.init(SERVER_KEYS.private)
        agreement.doPhase(clientKey, true)
        val secret = agreement.generateSecret()
        val aesKey = MessageDigest.getInstance("SHA-256").digest(SERVER_SALT + secret)
        val cipher = Cipher.getInstance(SecureEndpoint.AES_TRANSFORMATION)
        val gcmSpec = GCMParameterSpec(tagLength, iv)
        val mode = if (isDecrypt) Cipher.DECRYPT_MODE else Cipher.ENCRYPT_MODE
        cipher.init(mode, SecretKeySpec(aesKey, AES_ALGORITHM), gcmSpec)
        return cipher;
    }

}