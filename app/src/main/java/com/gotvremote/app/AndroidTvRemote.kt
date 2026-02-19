package com.gotvremote.app

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.*
import java.io.*
import java.math.BigInteger
import java.net.InetSocketAddress
import java.security.*
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * Android TV Remote Protocol v2 implementation.
 * Controls Android TV / GOtv streamer over WiFi.
 *
 * Protocol: TLS connection on port 6466 (commands) and 6467 (pairing)
 * Based on the protocol used by the Google TV mobile app.
 */
class AndroidTvRemote(private val context: Context) {

    interface Listener {
        fun onConnected()
        fun onDisconnected()
        fun onPairingRequired(pairingCode: String? = null)
        fun onPairingComplete()
        fun onError(message: String)
        fun onVolumeChanged(volume: Int, max: Int)
    }

    var listener: Listener? = null

    private val prefs: SharedPreferences =
        context.getSharedPreferences("atv_remote", Context.MODE_PRIVATE)

    private var commandSocket: SSLSocket? = null
    private var commandOut: OutputStream? = null
    private var commandIn: InputStream? = null

    private var pairingSocket: SSLSocket? = null
    private var pairingOut: OutputStream? = null
    private var pairingIn: InputStream? = null

    private var keyStore: KeyStore? = null
    private var sslContext: SSLContext? = null

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var readerJob: Job? = null
    private var pingJob: Job? = null

    @Volatile
    var isConnected = false
        private set

    @Volatile
    var isPaired = false
        private set

    private var serverHost: String = ""

    companion object {
        const val COMMAND_PORT = 6466
        const val PAIRING_PORT = 6467
        const val CONNECT_TIMEOUT_MS = 5000

        // Android KeyEvent codes
        const val KEYCODE_POWER = 26
        const val KEYCODE_HOME = 3
        const val KEYCODE_BACK = 4
        const val KEYCODE_DPAD_UP = 19
        const val KEYCODE_DPAD_DOWN = 20
        const val KEYCODE_DPAD_LEFT = 21
        const val KEYCODE_DPAD_RIGHT = 22
        const val KEYCODE_DPAD_CENTER = 23
        const val KEYCODE_VOLUME_UP = 24
        const val KEYCODE_VOLUME_DOWN = 25
        const val KEYCODE_VOLUME_MUTE = 164
        const val KEYCODE_CHANNEL_UP = 166
        const val KEYCODE_CHANNEL_DOWN = 167
        const val KEYCODE_0 = 7
        const val KEYCODE_1 = 8
        const val KEYCODE_2 = 9
        const val KEYCODE_3 = 10
        const val KEYCODE_4 = 11
        const val KEYCODE_5 = 12
        const val KEYCODE_6 = 13
        const val KEYCODE_7 = 14
        const val KEYCODE_8 = 15
        const val KEYCODE_9 = 16
        const val KEYCODE_ENTER = 66
        const val KEYCODE_MENU = 82
        const val KEYCODE_GUIDE = 172
        const val KEYCODE_INFO = 165
        const val KEYCODE_MEDIA_PLAY_PAUSE = 85
        const val KEYCODE_MEDIA_STOP = 86
        const val KEYCODE_MEDIA_NEXT = 87
        const val KEYCODE_MEDIA_PREVIOUS = 88
        const val KEYCODE_MEDIA_REWIND = 89
        const val KEYCODE_MEDIA_FAST_FORWARD = 90
        const val KEYCODE_MEDIA_RECORD = 130
        const val KEYCODE_TV_INPUT = 178
        const val KEYCODE_BOOKMARK = 174 // FAV
        const val KEYCODE_LAST_CHANNEL = 229
        const val KEYCODE_CAPTIONS = 175 // SUB
        const val KEYCODE_MEDIA_AUDIO_TRACK = 222
        const val KEYCODE_TV = 170
        const val KEYCODE_SETTINGS = 176

        // Button name to KeyCode mapping
        val KEY_MAP = mapOf(
            "POWER" to KEYCODE_POWER,
            "HOME" to KEYCODE_HOME,
            "BACK" to KEYCODE_BACK,
            "UP" to KEYCODE_DPAD_UP,
            "DOWN" to KEYCODE_DPAD_DOWN,
            "LEFT" to KEYCODE_DPAD_LEFT,
            "RIGHT" to KEYCODE_DPAD_RIGHT,
            "OK" to KEYCODE_DPAD_CENTER,
            "VOL_UP" to KEYCODE_VOLUME_UP,
            "VOL_DOWN" to KEYCODE_VOLUME_DOWN,
            "MUTE" to KEYCODE_VOLUME_MUTE,
            "CH_UP" to KEYCODE_CHANNEL_UP,
            "CH_DOWN" to KEYCODE_CHANNEL_DOWN,
            "0" to KEYCODE_0,
            "1" to KEYCODE_1,
            "2" to KEYCODE_2,
            "3" to KEYCODE_3,
            "4" to KEYCODE_4,
            "5" to KEYCODE_5,
            "6" to KEYCODE_6,
            "7" to KEYCODE_7,
            "8" to KEYCODE_8,
            "9" to KEYCODE_9,
            "MENU" to KEYCODE_MENU,
            "GUIDE" to KEYCODE_GUIDE,
            "INFO" to KEYCODE_INFO,
            "INPUT" to KEYCODE_TV_INPUT,
            "PLAY_PAUSE" to KEYCODE_MEDIA_PLAY_PAUSE,
            "STOP" to KEYCODE_MEDIA_STOP,
            "REWIND" to KEYCODE_MEDIA_REWIND,
            "FAST_FORWARD" to KEYCODE_MEDIA_FAST_FORWARD,
            "RECORD" to KEYCODE_MEDIA_RECORD,
            "FAV" to KEYCODE_BOOKMARK,
            "LAST" to KEYCODE_LAST_CHANNEL,
            "SUBTITLE" to KEYCODE_CAPTIONS,
            "AUDIO" to KEYCODE_MEDIA_AUDIO_TRACK,
            "EPG" to KEYCODE_GUIDE,
            "ENTER" to KEYCODE_ENTER
        )
    }

    // ===================== SSL / Certificate Management =====================

    private fun getOrCreateKeyStore(): KeyStore {
        keyStore?.let { return it }

        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        val certFile = File(context.filesDir, "atv_keystore.bks")

        if (certFile.exists()) {
            try {
                certFile.inputStream().use { ks.load(it, "gotvremote".toCharArray()) }
                keyStore = ks
                return ks
            } catch (e: Exception) {
                certFile.delete()
            }
        }

        // Generate new self-signed certificate
        ks.load(null, null)
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.generateKeyPair()

        val cert = generateSelfSignedCert(keyPair)
        ks.setKeyEntry("atv_client", keyPair.private, "gotvremote".toCharArray(), arrayOf(cert))

        certFile.outputStream().use { ks.store(it, "gotvremote".toCharArray()) }
        keyStore = ks
        return ks
    }

    private fun generateSelfSignedCert(keyPair: KeyPair): X509Certificate {
        val subject = "CN=GOtv Remote, O=GOtvRemote, L=Home"
        val sn = BigInteger.valueOf(System.currentTimeMillis())
        val notBefore = java.util.Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000)
        val notAfter = java.util.Date(System.currentTimeMillis() + 10L * 365 * 24 * 60 * 60 * 1000)

        // Use Android's built-in X509 generator
        val gen = Class.forName("android.security.keystore.AndroidKeyStoreProvider")
        // Fallback: use Bouncy Castle style self-signed cert generation via reflection
        // For simplicity, use a basic approach that works on Android
        return createCertificateViaAndroid(keyPair, subject, sn, notBefore, notAfter)
    }

    @Suppress("DEPRECATION")
    private fun createCertificateViaAndroid(
        keyPair: KeyPair, subject: String, serialNumber: BigInteger,
        notBefore: java.util.Date, notAfter: java.util.Date
    ): X509Certificate {
        // Use android.sun.security for self-signed cert generation
        try {
            val x500Name = Class.forName("sun.security.x509.X500Name")
                .getConstructor(String::class.java).newInstance(subject)

            val certInfoClass = Class.forName("sun.security.x509.X509CertInfo")
            val certInfo = certInfoClass.newInstance()

            val certImplClass = Class.forName("sun.security.x509.X509CertImpl")
            val algIdClass = Class.forName("sun.security.x509.AlgorithmId")
            val certValClass = Class.forName("sun.security.x509.CertificateValidity")
            val serialNumClass = Class.forName("sun.security.x509.CertificateSerialNumber")
            val certVersionClass = Class.forName("sun.security.x509.CertificateVersion")

            val validity = certValClass.getConstructor(java.util.Date::class.java, java.util.Date::class.java)
                .newInstance(notBefore, notAfter)

            val setMethod = certInfoClass.getMethod("set", String::class.java, Any::class.java)
            setMethod.invoke(certInfo, "validity", validity)
            setMethod.invoke(certInfo, "serialNumber",
                serialNumClass.getConstructor(BigInteger::class.java).newInstance(serialNumber))
            setMethod.invoke(certInfo, "subject", x500Name)
            setMethod.invoke(certInfo, "issuer", x500Name)
            setMethod.invoke(certInfo, "key",
                Class.forName("sun.security.x509.CertificateX509Key")
                    .getConstructor(PublicKey::class.java).newInstance(keyPair.public))
            setMethod.invoke(certInfo, "version",
                certVersionClass.getConstructor(Int::class.java).newInstance(2))

            val algId = algIdClass.getMethod("get", String::class.java).invoke(null, "SHA256withRSA")
            setMethod.invoke(certInfo, "algorithmID",
                Class.forName("sun.security.x509.CertificateAlgorithmId")
                    .getConstructor(algIdClass).newInstance(algId))

            val cert = certImplClass.getConstructor(certInfoClass).newInstance(certInfo) as X509Certificate
            certImplClass.getMethod("sign", PrivateKey::class.java, String::class.java)
                .invoke(cert, keyPair.private, "SHA256withRSA")

            return cert
        } catch (e: Exception) {
            // Fallback: simple DER-based self-signed certificate
            return createSimpleSelfSignedCert(keyPair, notBefore, notAfter, serialNumber)
        }
    }

    private fun createSimpleSelfSignedCert(
        keyPair: KeyPair,
        notBefore: java.util.Date,
        notAfter: java.util.Date,
        serialNumber: BigInteger
    ): X509Certificate {
        // Build a minimal X.509v3 cert using raw DER encoding
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(keyPair.private)

        val subject = "CN=GOtv Remote"
        val tbsCert = buildTbsCertificate(keyPair.public, subject, serialNumber, notBefore, notAfter)
        sig.update(tbsCert)
        val signature = sig.sign()

        val certDer = buildSignedCertificate(tbsCert, signature)
        val cf = java.security.cert.CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
    }

    private fun buildTbsCertificate(
        publicKey: PublicKey, subject: String, serial: BigInteger,
        notBefore: java.util.Date, notAfter: java.util.Date
    ): ByteArray {
        val out = ByteArrayOutputStream()

        // Version v3
        out.write(derTag(0xA0, derInt(2)))
        // Serial number
        out.write(derInt(serial))
        // Signature algorithm: SHA256withRSA
        out.write(derSequence(derOid(byteArrayOf(0x2A.toByte(), 0x86.toByte(), 0x48.toByte(), 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B)) + derNull()))
        // Issuer
        out.write(derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)) + derUtf8(subject.removePrefix("CN="))))))
        // Validity
        out.write(derSequence(derUtcTime(notBefore) + derUtcTime(notAfter)))
        // Subject
        out.write(derSequence(derSet(derSequence(derOid(byteArrayOf(0x55, 0x04, 0x03)) + derUtf8(subject.removePrefix("CN="))))))
        // Public key info
        out.write(publicKey.encoded)

        return derSequence(out.toByteArray())
    }

    private fun buildSignedCertificate(tbsCert: ByteArray, signature: ByteArray): ByteArray {
        val sigAlg = derSequence(derOid(byteArrayOf(0x2A.toByte(), 0x86.toByte(), 0x48.toByte(), 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B)) + derNull())
        val sigBits = derBitString(signature)
        return derSequence(tbsCert + sigAlg + sigBits)
    }

    // DER encoding helpers
    private fun derTag(tag: Int, content: ByteArray): ByteArray =
        byteArrayOf(tag.toByte()) + derLength(content.size) + content

    private fun derSequence(content: ByteArray): ByteArray = derTag(0x30, content)
    private fun derSet(content: ByteArray): ByteArray = derTag(0x31, content)
    private fun derOid(oid: ByteArray): ByteArray = derTag(0x06, oid)
    private fun derNull(): ByteArray = byteArrayOf(0x05, 0x00)
    private fun derUtf8(s: String): ByteArray = derTag(0x0C, s.toByteArray(Charsets.UTF_8))
    private fun derBitString(data: ByteArray): ByteArray = derTag(0x03, byteArrayOf(0x00) + data)

    private fun derInt(value: Int): ByteArray = derInt(BigInteger.valueOf(value.toLong()))
    private fun derInt(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return derTag(0x02, bytes)
    }

    private fun derUtcTime(date: java.util.Date): ByteArray {
        val sdf = java.text.SimpleDateFormat("yyMMddHHmmss'Z'", java.util.Locale.US)
        sdf.timeZone = java.util.TimeZone.getTimeZone("UTC")
        return derTag(0x17, sdf.format(date).toByteArray(Charsets.US_ASCII))
    }

    private fun derLength(len: Int): ByteArray {
        if (len < 128) return byteArrayOf(len.toByte())
        val bytes = BigInteger.valueOf(len.toLong()).toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes
    }

    private fun getSSLContext(): SSLContext {
        sslContext?.let { return it }

        val ks = getOrCreateKeyStore()
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, "gotvremote".toCharArray())

        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })

        val ctx = SSLContext.getInstance("TLSv1.2")
        ctx.init(kmf.keyManagers, trustAll, SecureRandom())
        sslContext = ctx
        return ctx
    }

    // ===================== Connection =====================

    fun connect(host: String) {
        serverHost = host
        prefs.edit().putString("last_host", host).apply()

        scope.launch {
            try {
                val sf = getSSLContext().socketFactory

                // Try connecting to command port
                val socket = sf.createSocket() as SSLSocket
                socket.connect(InetSocketAddress(host, COMMAND_PORT), CONNECT_TIMEOUT_MS)
                socket.soTimeout = 0
                socket.startHandshake()

                commandSocket = socket
                commandOut = socket.outputStream
                commandIn = socket.inputStream

                // Check if we need to pair (server will close if not paired)
                isPaired = true
                isConnected = true

                // Send initial configuration
                sendConfiguration()

                // Start reading responses
                startReader()
                startPingPong()

                withContext(Dispatchers.Main) {
                    listener?.onConnected()
                }
            } catch (e: javax.net.ssl.SSLHandshakeException) {
                // Not paired yet - need to pair first
                isPaired = false
                isConnected = false
                withContext(Dispatchers.Main) {
                    listener?.onPairingRequired()
                }
                startPairing(host)
            } catch (e: Exception) {
                isConnected = false
                withContext(Dispatchers.Main) {
                    listener?.onError("Connection failed: ${e.message}")
                }
            }
        }
    }

    // ===================== Pairing =====================

    private fun startPairing(host: String) {
        scope.launch {
            try {
                val sf = getSSLContext().socketFactory
                val socket = sf.createSocket() as SSLSocket
                socket.connect(InetSocketAddress(host, PAIRING_PORT), CONNECT_TIMEOUT_MS)
                socket.startHandshake()

                pairingSocket = socket
                pairingOut = socket.outputStream
                pairingIn = socket.inputStream

                // Step 1: Send pairing request
                sendPairingRequest()

                // Step 2: Send option message
                sendPairingOptions()

                // Step 3: Send configuration message
                sendPairingConfiguration()

                // Read server response - a code should appear on TV
                readPairingResponse()

                withContext(Dispatchers.Main) {
                    listener?.onPairingRequired("Enter the code shown on your TV")
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    listener?.onError("Pairing failed: ${e.message}")
                }
            }
        }
    }

    private fun sendPairingRequest() {
        val serviceName = "com.gotvremote.app"
        val deviceName = "GOtv Remote"

        val payload = ByteArrayOutputStream()
        // Protocol version
        payload.write(byteArrayOf(8, 2))
        // Status OK
        payload.write(byteArrayOf(16, 200.toByte(), 1))
        // Pairing request tag (82 = field 10, type 2)
        val innerPayload = ByteArrayOutputStream()
        // Service name (field 1)
        innerPayload.write(writeProtobufString(1, serviceName))
        // Device name (field 2)
        innerPayload.write(writeProtobufString(2, deviceName))
        payload.write(writeProtobufBytes(10, innerPayload.toByteArray()))

        sendPairingMessage(payload.toByteArray())
    }

    private fun sendPairingOptions() {
        // Option message: encoding=HEXADECIMAL(3), type=INPUT_DEVICE(6), preferred_role=INPUT(1)
        val payload = byteArrayOf(8, 2, 16, 200.toByte(), 1, 162.toByte(), 1, 8, 10, 4, 8, 3, 16, 6, 24, 1)
        sendPairingMessage(payload)
    }

    private fun sendPairingConfiguration() {
        // Configuration message
        val payload = byteArrayOf(8, 2, 16, 200.toByte(), 1, 242.toByte(), 1, 8, 10, 4, 8, 3, 16, 6, 16, 1)
        sendPairingMessage(payload)
    }

    fun submitPairingCode(code: String) {
        scope.launch {
            try {
                val secret = computePairingSecret(code)
                sendPairingSecret(secret)

                // Read response
                val response = readPairingBytes()
                if (response != null && response.size > 4) {
                    // Check for success status (200)
                    isPaired = true
                    closePairing()

                    withContext(Dispatchers.Main) {
                        listener?.onPairingComplete()
                    }

                    // Now connect with command channel
                    delay(500)
                    connect(serverHost)
                } else {
                    withContext(Dispatchers.Main) {
                        listener?.onError("Pairing failed - wrong code?")
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    listener?.onError("Pairing error: ${e.message}")
                }
            }
        }
    }

    private fun computePairingSecret(code: String): ByteArray {
        // The secret is computed from a SHA-256 hash combining
        // client cert, server cert, and the pairing code
        val md = MessageDigest.getInstance("SHA-256")

        // Get client certificate
        val ks = getOrCreateKeyStore()
        val clientCert = ks.getCertificate("atv_client") as? X509Certificate

        // Get server certificate from pairing socket
        val serverCert = pairingSocket?.session?.peerCertificates?.firstOrNull() as? X509Certificate

        if (clientCert != null) {
            val clientKey = clientCert.publicKey as java.security.interfaces.RSAPublicKey
            md.update(clientKey.modulus.toByteArray())
            md.update(clientKey.publicExponent.toByteArray())
        }

        if (serverCert != null) {
            val serverKey = serverCert.publicKey as java.security.interfaces.RSAPublicKey
            md.update(serverKey.modulus.toByteArray())
            md.update(serverKey.publicExponent.toByteArray())
        }

        // Add the code (convert hex characters)
        for (ch in code) {
            val hexValue = if (ch.isDigit()) ch - '0' else ch.uppercaseChar() - 'A' + 10
            md.update(byteArrayOf(hexValue.toByte()))
        }

        return md.digest()
    }

    private fun sendPairingSecret(secret: ByteArray) {
        val payload = ByteArrayOutputStream()
        payload.write(byteArrayOf(8, 2, 16, 200.toByte(), 1))
        // Secret tag (field 12)
        payload.write(writeProtobufBytes(12, secret))
        sendPairingMessage(payload.toByteArray())
    }

    private fun sendPairingMessage(data: ByteArray) {
        val out = pairingOut ?: return
        synchronized(out) {
            out.write(data.size)
            out.write(data)
            out.flush()
        }
    }

    private fun readPairingResponse() {
        readPairingBytes() // Read acknowledgment messages
        readPairingBytes()
    }

    private fun readPairingBytes(): ByteArray? {
        val input = pairingIn ?: return null
        return try {
            val size = input.read()
            if (size <= 0) return null
            val data = ByteArray(size)
            var read = 0
            while (read < size) {
                val n = input.read(data, read, size - read)
                if (n <= 0) break
                read += n
            }
            data
        } catch (e: Exception) {
            null
        }
    }

    private fun closePairing() {
        try { pairingSocket?.close() } catch (_: Exception) {}
        pairingSocket = null
        pairingOut = null
        pairingIn = null
    }

    // ===================== Command Sending =====================

    private fun sendConfiguration() {
        // Send initial config to identify ourselves as a remote
        // Field 1: config message
        val config = ByteArrayOutputStream()
        // model = 622 (device type)
        config.write(writeProtobufVarint(1, 622))
        // app_version
        config.write(writeProtobufString(3, "1"))
        // vendor
        config.write(writeProtobufString(4, "1"))
        // model_name = "androidtv-remote2"
        config.write(writeProtobufString(5, "androidtv-remote2"))
        // version
        config.write(writeProtobufString(6, "1.0.0"))

        val wrapper = ByteArrayOutputStream()
        wrapper.write(writeProtobufBytes(1, config.toByteArray()))
        sendCommandMessage(wrapper.toByteArray())

        // Send device info
        val devInfo = ByteArrayOutputStream()
        devInfo.write(writeProtobufVarint(1, 622))
        sendCommandMessage(writeProtobufBytes(2, devInfo.toByteArray()))
    }

    /**
     * Send a key press event.
     * @param keyCode Android KeyEvent constant
     * @param action 1=ACTION_DOWN, 2=ACTION_UP, 3=SHORT_PRESS (down+up)
     */
    fun sendKeyEvent(keyCode: Int, action: Int = 3) {
        if (!isConnected) return

        scope.launch {
            try {
                if (action == 3) {
                    // Short press: send DOWN then UP
                    sendKeyAction(keyCode, 1) // DOWN
                    delay(50)
                    sendKeyAction(keyCode, 2) // UP
                } else {
                    sendKeyAction(keyCode, action)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    listener?.onError("Send failed: ${e.message}")
                }
            }
        }
    }

    private fun sendKeyAction(keyCode: Int, action: Int) {
        // Key event message: field 10, then keyCode and action
        val inner = ByteArrayOutputStream()
        inner.write(writeProtobufVarint(1, keyCode))
        inner.write(writeProtobufVarint(2, action))
        val msg = writeProtobufBytes(10, inner.toByteArray())
        sendCommandMessage(msg)
    }

    /**
     * Send a command by button name (e.g. "POWER", "VOL_UP", "OK")
     */
    fun sendCommand(buttonName: String): Boolean {
        val keyCode = KEY_MAP[buttonName] ?: return false
        sendKeyEvent(keyCode)
        return true
    }

    private fun sendCommandMessage(data: ByteArray) {
        val out = commandOut ?: return
        try {
            synchronized(out) {
                // Write length as varint
                writeVarint(out, data.size)
                out.write(data)
                out.flush()
            }
        } catch (e: Exception) {
            handleDisconnect()
        }
    }

    // ===================== Reading & Ping/Pong =====================

    private fun startReader() {
        readerJob = scope.launch {
            try {
                val input = commandIn ?: return@launch
                while (isActive && isConnected) {
                    val size = readVarint(input)
                    if (size <= 0) {
                        handleDisconnect()
                        break
                    }
                    val data = ByteArray(size)
                    var read = 0
                    while (read < size) {
                        val n = input.read(data, read, size - read)
                        if (n <= 0) {
                            handleDisconnect()
                            return@launch
                        }
                        read += n
                    }
                    handleMessage(data)
                }
            } catch (e: Exception) {
                handleDisconnect()
            }
        }
    }

    private fun startPingPong() {
        pingJob = scope.launch {
            while (isActive && isConnected) {
                delay(5000)
                // Send ping/keepalive
                try {
                    val ping = byteArrayOf(74, 2, 8, 25)
                    commandOut?.let { out ->
                        synchronized(out) {
                            out.write(ping)
                            out.flush()
                        }
                    }
                } catch (e: Exception) {
                    handleDisconnect()
                    break
                }
            }
        }
    }

    private fun handleMessage(data: ByteArray) {
        // Parse incoming messages (volume changes, power state, etc.)
        if (data.size >= 2) {
            // Check for ping (starts with 66, 6)
            if (data[0] == 66.toByte()) {
                // Respond with pong
                try {
                    val pong = byteArrayOf(74, 2, 8, 25)
                    commandOut?.let { out ->
                        synchronized(out) {
                            out.write(pong)
                            out.flush()
                        }
                    }
                } catch (_: Exception) {}
            }
        }
    }

    private fun handleDisconnect() {
        if (!isConnected) return
        isConnected = false
        readerJob?.cancel()
        pingJob?.cancel()
        scope.launch(Dispatchers.Main) {
            listener?.onDisconnected()
        }
    }

    // ===================== Protobuf helpers =====================

    private fun writeProtobufVarint(fieldNumber: Int, value: Int): ByteArray {
        val out = ByteArrayOutputStream()
        // Field tag (field_number << 3 | 0)
        writeVarint(out, (fieldNumber shl 3) or 0)
        writeVarint(out, value)
        return out.toByteArray()
    }

    private fun writeProtobufString(fieldNumber: Int, value: String): ByteArray {
        return writeProtobufBytes(fieldNumber, value.toByteArray(Charsets.UTF_8))
    }

    private fun writeProtobufBytes(fieldNumber: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        // Field tag (field_number << 3 | 2)
        writeVarint(out, (fieldNumber shl 3) or 2)
        writeVarint(out, value.size)
        out.write(value)
        return out.toByteArray()
    }

    private fun writeVarint(out: OutputStream, value: Int) {
        var v = value
        while (v > 0x7F) {
            out.write((v and 0x7F) or 0x80)
            v = v ushr 7
        }
        out.write(v and 0x7F)
    }

    private fun readVarint(input: InputStream): Int {
        var result = 0
        var shift = 0
        while (true) {
            val b = input.read()
            if (b == -1) return -1
            result = result or ((b and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 35) return -1
        }
        return result
    }

    // ===================== Lifecycle =====================

    fun getLastHost(): String? = prefs.getString("last_host", null)

    fun disconnect() {
        isConnected = false
        isPaired = false
        readerJob?.cancel()
        pingJob?.cancel()
        try { commandSocket?.close() } catch (_: Exception) {}
        closePairing()
        commandSocket = null
        commandOut = null
        commandIn = null
    }

    fun destroy() {
        disconnect()
        scope.cancel()
    }
}
