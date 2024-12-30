package com.seblit.security.cryptochannel

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class SecureServerTest {

    companion object {

        private const val AES_ALGORITHM = "AES"
        private lateinit var CLIENT_KEYS: KeyPair
        private lateinit var CLIENT_IV: ByteArray
        private lateinit var SESSION_AES_KEY: ByteArray
        private lateinit var SESSION_SALT: ByteArray
        private lateinit var SESSION_ID: ByteArray
        private lateinit var DATA: ByteArray
        private lateinit var ENCRYPTED_SESSION_DATA: ByteArray

        @JvmStatic
        @BeforeAll
        fun setupTest() {
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec(SecureEndpoint.DEFAULT_CURVE))
            CLIENT_KEYS = generator.generateKeyPair()
            val random = SecureRandom()
            CLIENT_IV = ByteArray(SecureEndpoint.DEFAULT_IV_LENGTH).apply { random.nextBytes(this) }
            SESSION_SALT = ByteArray(256).apply { random.nextBytes(this) }
            DATA = ByteArray(10).apply { random.nextBytes(this) }
            SESSION_ID = ByteArray(10).apply { random.nextBytes(this) }
            SESSION_AES_KEY = deriveAesKey(CLIENT_KEYS.public, CLIENT_KEYS.private, SESSION_SALT)
            ENCRYPTED_SESSION_DATA =
                createCipher(false, CLIENT_IV, SecureEndpoint.DEFAULT_TAG_LENGTH, SESSION_AES_KEY).doFinal(DATA)

        }

        @JvmStatic
        private fun deriveAesKey(partnerKey: PublicKey, myKey: PrivateKey, secretSalt:ByteArray): ByteArray {
            val agreement = KeyAgreement.getInstance(SecureEndpoint.KEY_AGREEMENT)
            agreement.init(myKey)
            agreement.doPhase(partnerKey, true)
            val secret = agreement.generateSecret()
            return MessageDigest.getInstance("SHA-256").digest(secretSalt+secret)
        }

        @JvmStatic
        private fun createCipher(isDecrypt: Boolean, iv: ByteArray, tagLength: Int, aesKey: ByteArray): Cipher {
            val cipher = Cipher.getInstance(SecureEndpoint.AES_TRANSFORMATION)
            val gcmSpec = GCMParameterSpec(tagLength, iv)
            val mode = if (isDecrypt) Cipher.DECRYPT_MODE else Cipher.ENCRYPT_MODE
            cipher.init(mode, SecretKeySpec(aesKey, AES_ALGORITHM), gcmSpec)
            return cipher
        }
    }

    private lateinit var server: SecureServer<ByteArray>
    private lateinit var mockedSessionManager: SecureServer.SessionManager<ByteArray>

    @BeforeEach
    fun setup() {
        mockedSessionManager = mock()
        whenever(mockedSessionManager.storeSession(any<ByteArray>())).thenReturn(SESSION_ID)
        whenever(mockedSessionManager.loadSession(any<ByteArray>())).thenReturn(SESSION_AES_KEY)
        server = SecureServer(mockedSessionManager)
    }

    @Test
    fun testEncryptDownload() {
        val response = server.encryptDownload(DATA, CLIENT_KEYS.public)
        val decData =
            createCipher(
                true,
                response.iv,
                response.tagLength,
                deriveAesKey(response.pubKey, CLIENT_KEYS.private, response.secretSalt)
            ).doFinal(response.encData)
        assertArrayEquals(DATA, decData)
    }

    @Test
    fun testEncryptDownstream() {
        val target = ByteArrayOutputStream()
        val response = server.encryptDownstream(target, CLIENT_KEYS.public)
        response.encData.use { it.write(DATA) }
        val decData = createCipher(
            true,
            response.iv,
            response.tagLength,
            deriveAesKey(response.pubKey, CLIENT_KEYS.private, response.secretSalt)
        ).doFinal(target.use { it.toByteArray() })
        assertArrayEquals(DATA, decData)
    }

    @Test
    fun testInitializeAESSession() {
        val uploadResponse = server.initializeAESSession(CLIENT_KEYS.public)
        val aesKey = deriveAesKey(uploadResponse.pubKey, CLIENT_KEYS.private, uploadResponse.secretSalt)
        val aesKeyCaptor = argumentCaptor<ByteArray>()
        verify(mockedSessionManager).storeSession( aesKeyCaptor.capture())
        assertArrayEquals(aesKey, aesKeyCaptor.lastValue)
    }

    @Test
    fun testDecryptUpload() {
        val decryptedData = server.decryptUpload(
            SecureEndpoint.UploadRequest(
                SecureEndpoint.DEFAULT_TAG_LENGTH,
                CLIENT_IV,
                SESSION_ID
            ), ENCRYPTED_SESSION_DATA
        )
        assertArrayEquals(DATA, decryptedData)
        verify(mockedSessionManager).loadSession(SESSION_ID)
    }

    @Test
    fun testDecryptUpstream() {
        val source = ByteArrayInputStream(ENCRYPTED_SESSION_DATA)
        val decryptStream = server.decryptUpstream(
            SecureEndpoint.UploadRequest(
                SecureEndpoint.DEFAULT_TAG_LENGTH,
                CLIENT_IV,
                SESSION_ID
            ), source
        )
        val transformer = ByteArrayOutputStream()
        decryptStream.use { it.transferTo(transformer) }
        assertArrayEquals(DATA, transformer.use { it.toByteArray() })
        verify(mockedSessionManager).loadSession(SESSION_ID)
    }

}