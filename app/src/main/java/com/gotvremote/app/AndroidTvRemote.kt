package com.gotvremote.app

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.coroutines.*
import java.io.*
import java.math.BigInteger
import java.net.InetSocketAddress
import java.security.*
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import javax.net.ssl.*

/**
 * Android TV Remote Protocol v2 implementation.
 * Controls Android TV / GOtv streamer over WiFi.
 *
 * Protocol based on: https://github.com/tronikos/androidtvremote2
 * Pairing: port 6467, Commands: port 6466
 * Uses protobuf-like manual encoding (no protobuf dependency needed).
 */
class AndroidTvRemote(private val context: Context) {

    interface Listener {
        fun onConnected()
        fun onDisconnected()
        fun onReconnecting(attempt: Int, nextRetrySeconds: Int)
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
    private var reconnectJob: Job? = null

    @Volatile var isConnected = false; private set
    @Volatile var isPaired = false; private set
    @Volatile private var userDisconnected = false  // true when user explicitly disconnects

    private var serverHost: String = ""

    companion object {
        private const val TAG = "AtvRemote"
        const val COMMAND_PORT = 6466
        const val PAIRING_PORT = 6467
        const val CONNECT_TIMEOUT_MS = 5000

        // Feature flags for Android TV Remote Protocol v2
        private const val FEATURE_PING = 1
        private const val FEATURE_KEY = 2
        private const val FEATURE_POWER = 32
        private const val FEATURE_VOLUME = 64
        private const val FEATURE_APP_LINK = 512
        // Our requested features = PING | KEY | POWER | VOLUME | APP_LINK = 611
        private const val ACTIVE_FEATURES = FEATURE_PING or FEATURE_KEY or FEATURE_POWER or FEATURE_VOLUME or FEATURE_APP_LINK

        // Android KeyEvent codes
        val KEY_MAP = mapOf(
            "POWER" to 26, "HOME" to 3, "BACK" to 4,
            "UP" to 19, "DOWN" to 20, "LEFT" to 21, "RIGHT" to 22, "OK" to 23,
            "VOL_UP" to 24, "VOL_DOWN" to 25, "MUTE" to 164,
            "CH_UP" to 166, "CH_DOWN" to 167,
            "0" to 7, "1" to 8, "2" to 9, "3" to 10, "4" to 11,
            "5" to 12, "6" to 13, "7" to 14, "8" to 15, "9" to 16,
            "MENU" to 82, "GUIDE" to 172, "INFO" to 165, "INPUT" to 178,
            "PLAY_PAUSE" to 85, "STOP" to 86, "REWIND" to 89,
            "FAST_FORWARD" to 90, "RECORD" to 130,
            "FAV" to 174, "LAST" to 229, "SUBTITLE" to 175,
            "AUDIO" to 222, "EPG" to 172, "ENTER" to 66
        )
    }

    // ===================== SSL / Certificate =====================

    private fun getOrCreateKeyStore(): KeyStore {
        keyStore?.let { return it }
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        val certFile = File(context.filesDir, "atv_keystore.bks")

        if (certFile.exists()) {
            try {
                certFile.inputStream().use { ks.load(it, "gotvremote".toCharArray()) }
                keyStore = ks
                return ks
            } catch (e: Exception) { certFile.delete() }
        }

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

    @Suppress("DEPRECATION")
    private fun generateSelfSignedCert(keyPair: KeyPair): X509Certificate {
        val subject = "CN=GOtv Remote"
        val sn = BigInteger.valueOf(System.currentTimeMillis())
        val notBefore = java.util.Date(System.currentTimeMillis() - 86400000)
        val notAfter = java.util.Date(System.currentTimeMillis() + 10L * 365 * 86400000)

        // Try sun.security (available on most Android versions)
        try {
            val x500 = Class.forName("sun.security.x509.X500Name")
                .getConstructor(String::class.java).newInstance(subject)
            val infoClass = Class.forName("sun.security.x509.X509CertInfo")
            val info = infoClass.newInstance()
            val set = infoClass.getMethod("set", String::class.java, Any::class.java)

            val validity = Class.forName("sun.security.x509.CertificateValidity")
                .getConstructor(java.util.Date::class.java, java.util.Date::class.java)
                .newInstance(notBefore, notAfter)

            set.invoke(info, "validity", validity)
            set.invoke(info, "serialNumber",
                Class.forName("sun.security.x509.CertificateSerialNumber")
                    .getConstructor(BigInteger::class.java).newInstance(sn))
            set.invoke(info, "subject", x500)
            set.invoke(info, "issuer", x500)
            set.invoke(info, "key",
                Class.forName("sun.security.x509.CertificateX509Key")
                    .getConstructor(PublicKey::class.java).newInstance(keyPair.public))
            set.invoke(info, "version",
                Class.forName("sun.security.x509.CertificateVersion")
                    .getConstructor(Int::class.java).newInstance(2))

            val algIdClass = Class.forName("sun.security.x509.AlgorithmId")
            val algId = algIdClass.getMethod("get", String::class.java).invoke(null, "SHA256withRSA")
            set.invoke(info, "algorithmID",
                Class.forName("sun.security.x509.CertificateAlgorithmId")
                    .getConstructor(algIdClass).newInstance(algId))

            val implClass = Class.forName("sun.security.x509.X509CertImpl")
            val cert = implClass.getConstructor(infoClass).newInstance(info) as X509Certificate
            implClass.getMethod("sign", PrivateKey::class.java, String::class.java)
                .invoke(cert, keyPair.private, "SHA256withRSA")
            return cert
        } catch (e: Exception) {
            Log.w(TAG, "sun.security failed, using DER fallback", e)
            return createDerCert(keyPair, notBefore, notAfter, sn)
        }
    }

    private fun createDerCert(kp: KeyPair, nb: java.util.Date, na: java.util.Date, sn: BigInteger): X509Certificate {
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(kp.private)
        val sdf = java.text.SimpleDateFormat("yyMMddHHmmss'Z'", java.util.Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
        val sha256rsa = byteArrayOf(0x2A.toByte(),0x86.toByte(),0x48.toByte(),0x86.toByte(),0xF7.toByte(),0x0D,0x01,0x01,0x0B)

        fun tag(t: Int, c: ByteArray): ByteArray {
            val len = if (c.size < 128) byteArrayOf(c.size.toByte())
            else { val b = BigInteger.valueOf(c.size.toLong()).toByteArray().dropWhile { it == 0.toByte() }.toByteArray(); byteArrayOf((0x80 or b.size).toByte()) + b }
            return byteArrayOf(t.toByte()) + len + c
        }
        fun seq(c: ByteArray) = tag(0x30, c)
        fun set(c: ByteArray) = tag(0x31, c)

        val cn = "GOtv Remote".toByteArray(Charsets.UTF_8)
        val name = seq(set(seq(tag(0x06, byteArrayOf(0x55,0x04,0x03)) + tag(0x0C, cn))))
        val validity = seq(tag(0x17, sdf.format(nb).toByteArray()) + tag(0x17, sdf.format(na).toByteArray()))
        val algSeq = seq(tag(0x06, sha256rsa) + byteArrayOf(0x05,0x00))

        val tbs = seq(tag(0xA0, tag(0x02, byteArrayOf(2))) + tag(0x02, sn.toByteArray()) + algSeq + name + validity + name + kp.public.encoded)
        sig.update(tbs); val s = sig.sign()
        val der = seq(tbs + algSeq + tag(0x03, byteArrayOf(0x00) + s))
        return java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
    }

    private fun getSSLContext(): SSLContext {
        sslContext?.let { return it }
        val ks = getOrCreateKeyStore()
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, "gotvremote".toCharArray())
        val tm = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
            override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
            override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
        })
        val ctx = SSLContext.getInstance("TLSv1.2")
        ctx.init(kmf.keyManagers, tm, SecureRandom())
        sslContext = ctx
        return ctx
    }

    // ===================== Connection =====================

    fun connect(host: String) {
        serverHost = host
        userDisconnected = false
        prefs.edit().putString("last_host", host).apply()
        reconnectJob?.cancel()

        scope.launch {
            try {
                val sf = getSSLContext().socketFactory
                val socket = sf.createSocket() as SSLSocket
                socket.connect(InetSocketAddress(host, COMMAND_PORT), CONNECT_TIMEOUT_MS)
                socket.soTimeout = 30000  // Timeout for initial handshake
                socket.startHandshake()

                commandSocket = socket
                commandOut = socket.outputStream
                commandIn = socket.inputStream

                isConnected = true
                isPaired = true

                // Discover and store MAC for Wake-on-LAN
                discoverAndStoreMac(host)

                // Start reading (server sends config first, then pings)
                startReader()

                withContext(Dispatchers.Main) { listener?.onConnected() }
            } catch (e: javax.net.ssl.SSLHandshakeException) {
                Log.d(TAG, "SSL handshake failed: ${e.message}")
                isConnected = false
                // Check if we already have a stored certificate (already paired before)
                val certFile = File(context.filesDir, "atv_keystore.bks")
                if (certFile.exists()) {
                    // Already paired before - streamer probably rejected old cert or is off
                    // Try deleting keystore and re-pairing
                    Log.d(TAG, "Have stored cert but handshake failed - need fresh pairing")
                    certFile.delete()
                    keyStore = null
                    sslContext = null
                }
                isPaired = false
                withContext(Dispatchers.Main) { listener?.onPairingRequired() }
                startPairing(host)
            } catch (e: java.net.ConnectException) {
                isConnected = false
                Log.d(TAG, "ConnectException: ${e.message}")
                // Streamer is off or unreachable - schedule auto-reconnect
                scheduleReconnect(host)
            } catch (e: java.net.SocketTimeoutException) {
                isConnected = false
                Log.d(TAG, "Connection timeout: ${e.message}")
                scheduleReconnect(host)
            } catch (e: Exception) {
                Log.e(TAG, "Connect error", e)
                isConnected = false
                // For any transient error, try to auto-reconnect if we have a saved host
                scheduleReconnect(host)
            }
        }
    }

    /** Schedule periodic reconnection attempts until successful or user-cancelled */
    private fun scheduleReconnect(host: String) {
        if (userDisconnected) return
        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            withContext(Dispatchers.Main) {
                listener?.onDisconnected()
            }
            var attempt = 0
            while (isActive && !isConnected && !userDisconnected) {
                attempt++
                val delaySeconds = when {
                    attempt <= 3 -> 5L    // First 3 attempts: every 5 seconds
                    attempt <= 10 -> 10L  // Next 7 attempts: every 10 seconds
                    else -> 30L           // After that: every 30 seconds
                }
                Log.d(TAG, "Auto-reconnect attempt #$attempt in ${delaySeconds}s")
                withContext(Dispatchers.Main) {
                    listener?.onReconnecting(attempt, delaySeconds.toInt())
                }
                delay(delaySeconds * 1000)

                if (!isActive || isConnected || userDisconnected) break

                // Try to connect
                try {
                    val sf = getSSLContext().socketFactory
                    val socket = sf.createSocket() as SSLSocket
                    socket.connect(InetSocketAddress(host, COMMAND_PORT), CONNECT_TIMEOUT_MS)
                    socket.soTimeout = 30000
                    socket.startHandshake()

                    commandSocket = socket
                    commandOut = socket.outputStream
                    commandIn = socket.inputStream

                    isConnected = true
                    isPaired = true

                    discoverAndStoreMac(host)
                    startReader()

                    withContext(Dispatchers.Main) { listener?.onConnected() }
                    Log.d(TAG, "Auto-reconnect succeeded on attempt #$attempt")
                    return@launch
                } catch (e: Exception) {
                    Log.d(TAG, "Auto-reconnect attempt #$attempt failed: ${e.message}")
                    // Continue loop
                }
            }
        }
    }

    // ===================== Pairing (Polo Protocol) =====================
    // OuterMessage fields: protocol_version=1, status=2, pairing_request=10,
    //   pairing_request_ack=11, options=20, configuration=30, secret=40, secret_ack=41
    // PairingRequest: service_name=1, client_name=2
    // Options: input_encodings=1 (Encoding: type=1, symbol_length=2), preferred_role=3
    // Configuration: encoding=1 (Encoding), client_role=2
    // Secret: secret=1

    private fun startPairing(host: String) {
        scope.launch {
            try {
                val sf = getSSLContext().socketFactory
                val socket = sf.createSocket() as SSLSocket
                socket.connect(InetSocketAddress(host, PAIRING_PORT), CONNECT_TIMEOUT_MS)
                socket.soTimeout = 10000
                socket.startHandshake()

                pairingSocket = socket
                pairingOut = socket.outputStream
                pairingIn = socket.inputStream

                // Step 1: Send pairing_request (field 10)
                Log.d(TAG, "Sending pairing request")
                val pairReq = ByteArrayOutputStream()
                pairReq.write(pbString(1, "atvremote"))  // service_name
                pairReq.write(pbString(2, "GOtv Remote")) // client_name
                sendPolo(buildOuterMessage(10, pairReq.toByteArray()))

                // Read pairing_request_ack
                val ack1 = readPoloMessage()
                Log.d(TAG, "Got ack1: ${ack1?.size} bytes")

                // Step 2: Send options (field 20)
                // Options: input_encodings (field 1) = [Encoding(type=HEXADECIMAL(3), symbol_length=6)]
                //          preferred_role (field 3) = ROLE_TYPE_INPUT (1)
                val encoding = pbVarint(1, 3) + pbVarint(2, 6)  // type=HEXADECIMAL, symbol_length=6
                val options = pbBytes(1, encoding) + pbVarint(3, 1)  // input_encodings + preferred_role=INPUT
                sendPolo(buildOuterMessage(20, options))

                // Read options response
                val ack2 = readPoloMessage()
                Log.d(TAG, "Got ack2: ${ack2?.size} bytes")

                // Step 3: Send configuration (field 30)
                // Configuration: encoding (field 1) = Encoding(type=3, symbol_length=6), client_role (field 2) = 1
                val config = pbBytes(1, encoding) + pbVarint(2, 1)
                sendPolo(buildOuterMessage(30, config))

                // Read configuration_ack - at this point code appears on TV
                val ack3 = readPoloMessage()
                Log.d(TAG, "Got ack3: ${ack3?.size} bytes")

                withContext(Dispatchers.Main) {
                    listener?.onPairingRequired("Enter the 6-character code shown on your TV")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Pairing start failed", e)
                withContext(Dispatchers.Main) {
                    listener?.onError("Pairing failed: ${e.message}")
                }
            }
        }
    }

    fun submitPairingCode(code: String) {
        scope.launch {
            try {
                val trimmed = code.trim().uppercase()
                if (trimmed.length != 6) {
                    withContext(Dispatchers.Main) {
                        listener?.onError("Code must be exactly 6 characters")
                    }
                    return@launch
                }

                // Validate hex
                try { trimmed.toLong(16) } catch (e: NumberFormatException) {
                    withContext(Dispatchers.Main) {
                        listener?.onError("Code must be hexadecimal (0-9, A-F)")
                    }
                    return@launch
                }

                // Compute secret hash
                val hash = computeSecret(trimmed)

                // Verify: first byte of hash must match first 2 hex chars of code
                val expectedFirstByte = trimmed.substring(0, 2).toInt(16)
                if ((hash[0].toInt() and 0xFF) != expectedFirstByte) {
                    Log.w(TAG, "Hash mismatch: hash[0]=${hash[0].toInt() and 0xFF}, expected=$expectedFirstByte")
                    withContext(Dispatchers.Main) {
                        listener?.onError("Invalid code - please check and try again")
                    }
                    // Restart pairing
                    closePairing()
                    startPairing(serverHost)
                    return@launch
                }

                // Send secret (field 40), inner secret on field 1
                val secretPayload = pbBytes(1, hash)
                sendPolo(buildOuterMessage(40, secretPayload))

                // Read secret_ack
                val ack = readPoloMessage()
                Log.d(TAG, "Got secret ack: ${ack?.size} bytes")

                isPaired = true
                closePairing()

                withContext(Dispatchers.Main) { listener?.onPairingComplete() }

                delay(1000)
                connect(serverHost)

            } catch (e: Exception) {
                Log.e(TAG, "Pairing code submission failed", e)
                withContext(Dispatchers.Main) {
                    listener?.onError("Pairing error: ${e.message}")
                }
                closePairing()
                startPairing(serverHost)
            }
        }
    }

    private fun computeSecret(code: String): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")

        // Client certificate modulus & exponent (as hex string bytes)
        val ks = getOrCreateKeyStore()
        val clientCert = ks.getCertificate("atv_client") as? X509Certificate
        if (clientCert != null) {
            val key = clientCert.publicKey as RSAPublicKey
            md.update(hexToBytes(key.modulus.toString(16).uppercase()))
            // Exponent: padded with leading 0
            md.update(hexToBytes("0" + key.publicExponent.toString(16).uppercase()))
        }

        // Server certificate modulus & exponent
        val serverCert = pairingSocket?.session?.peerCertificates?.firstOrNull() as? X509Certificate
        if (serverCert != null) {
            val key = serverCert.publicKey as RSAPublicKey
            md.update(hexToBytes(key.modulus.toString(16).uppercase()))
            md.update(hexToBytes("0" + key.publicExponent.toString(16).uppercase()))
        }

        // Last 4 hex chars of the code (indices 2..5)
        md.update(hexToBytes(code.substring(2)))

        return md.digest()
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = if (hex.length % 2 != 0) "0$hex" else hex
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun buildOuterMessage(fieldNumber: Int, payload: ByteArray): ByteArray {
        val msg = ByteArrayOutputStream()
        msg.write(pbVarint(1, 2))       // protocol_version = 2
        msg.write(pbVarint(2, 200))     // status = STATUS_OK (200)
        msg.write(pbBytes(fieldNumber, payload))
        return msg.toByteArray()
    }

    private fun sendPolo(data: ByteArray) {
        val out = pairingOut ?: return
        synchronized(out) {
            // Length-prefixed (single byte for small messages, varint for larger)
            val lenBuf = ByteArrayOutputStream()
            writeVarintTo(lenBuf, data.size)
            out.write(lenBuf.toByteArray())
            out.write(data)
            out.flush()
        }
    }

    private fun readPoloMessage(): ByteArray? {
        val input = pairingIn ?: return null
        return try {
            val size = readVarintFrom(input)
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
            Log.w(TAG, "readPoloMessage error: ${e.message}")
            null
        }
    }

    private fun closePairing() {
        try { pairingSocket?.close() } catch (_: Exception) {}
        pairingSocket = null; pairingOut = null; pairingIn = null
    }

    // ===================== Command Protocol (RemoteMessage) =====================
    // RemoteMessage fields (from remotemessage.proto):
    //   remote_configure=1, remote_set_active=2, remote_error=3,
    //   remote_ping_request=8, remote_ping_response=9,
    //   remote_key_inject=10,
    //   remote_ime_key_inject=20, remote_ime_batch_edit=21, remote_ime_show_request=22,
    //   remote_voice_begin=30, remote_voice_payload=31, remote_voice_end=32,
    //   remote_start=40,
    //   remote_set_volume_level=50, remote_adjust_volume_level=51,
    //   remote_set_preferred_audio_device=60, remote_reset_preferred_audio_device=61,
    //   remote_app_link_launch_request=90
    //
    // RemoteConfigure: code1=1, device_info=2
    // RemoteDeviceInfo: model=1, vendor=2, unknown1=3, unknown2=4, package_name=5, app_version=6
    // RemoteSetActive: active=1
    // RemotePingRequest: val1=1
    // RemotePingResponse: val1=1
    // RemoteKeyInject: key_code=1, direction=2
    // RemoteSetVolumeLevel: unknown1=1, unknown2=2, player_model=3, unknown4=4, unknown5=5,
    //   volume_max=6, volume_level=7, volume_muted=8
    // RemoteStart: started=1

    fun sendCommand(buttonName: String): Boolean {
        val keyCode = KEY_MAP[buttonName] ?: return false
        sendKeyEvent(keyCode)
        return true
    }

    fun sendKeyEvent(keyCode: Int) {
        if (!isConnected) return
        scope.launch {
            try {
                // RemoteDirection: START_LONG=1, END_LONG=2, SHORT=3
                // Volume/mute keys need START_LONG + END_LONG (press-release cycle)
                // because Android's audio framework requires it for system volume
                val isVolumeKey = keyCode == 24 || keyCode == 25 || keyCode == 164 // VOL_UP, VOL_DOWN, MUTE
                if (isVolumeKey) {
                    val down = pbBytes(10, pbVarint(1, keyCode) + pbVarint(2, 1)) // START_LONG
                    sendRemoteMessage(down)
                    delay(50)
                    val up = pbBytes(10, pbVarint(1, keyCode) + pbVarint(2, 2))   // END_LONG
                    sendRemoteMessage(up)
                } else {
                    val keyMsg = pbBytes(10, pbVarint(1, keyCode) + pbVarint(2, 3)) // SHORT
                    sendRemoteMessage(keyMsg)
                }
            } catch (e: Exception) {
                Log.e(TAG, "sendKeyEvent failed", e)
                withContext(Dispatchers.Main) { listener?.onError("Send failed") }
            }
        }
    }

    private fun sendRemoteMessage(data: ByteArray) {
        val out = commandOut ?: return
        try {
            synchronized(out) {
                val lenBuf = ByteArrayOutputStream()
                writeVarintTo(lenBuf, data.size)
                out.write(lenBuf.toByteArray())
                out.write(data)
                out.flush()
            }
        } catch (e: Exception) {
            handleDisconnect()
        }
    }

    private fun startReader() {
        readerJob = scope.launch {
            try {
                val input = commandIn ?: return@launch

                // Step 1: Read server's remote_configure message
                val firstMsg = readCommandMessage(input)
                if (firstMsg == null) {
                    Log.e(TAG, "No server config received")
                    handleDisconnect()
                    return@launch
                }
                Log.d(TAG, "Server config: ${firstMsg.size} bytes: ${firstMsg.joinToString(",") { (it.toInt() and 0xFF).toString() }}")

                // Parse server's supported features from remote_configure.code1 (field 1, sub-field 1)
                val configPayload = extractFieldBytes(firstMsg, 1)
                val serverFeatures = if (configPayload != null) extractVarintField(configPayload, 1) else ACTIVE_FEATURES
                Log.d(TAG, "Server features: $serverFeatures")

                // Compute negotiated features = ours AND server's
                val negotiatedFeatures = ACTIVE_FEATURES and serverFeatures
                Log.d(TAG, "Negotiated features: $negotiatedFeatures")

                // Step 2: Send our remote_configure response
                // RemoteConfigure (field 1): code1 (field 1) = negotiated features, device_info (field 2)
                // RemoteDeviceInfo: unknown1 (field 3) = 1, unknown2 (field 4) = "1",
                //   package_name (field 5) = "atvremote", app_version (field 6) = "1.0.0"
                val devInfo = pbVarint(3, 1) + pbString(4, "1") + pbString(5, "atvremote") + pbString(6, "1.0.0")
                val configResp = pbBytes(1, pbVarint(1, negotiatedFeatures) + pbBytes(2, devInfo))
                sendRemoteMessage(configResp)
                Log.d(TAG, "Sent config response with features=$negotiatedFeatures")

                // Step 3: Read and handle messages (set_active, start, pings)
                // The server will send: remote_set_active, then remote_start, then pings
                commandSocket?.soTimeout = 0  // Remove read timeout for long-lived connection
                while (isActive && isConnected) {
                    val msg = readCommandMessage(input)
                    if (msg == null) {
                        handleDisconnect()
                        break
                    }
                    handleRemoteMessage(msg)
                }
            } catch (e: Exception) {
                Log.w(TAG, "Reader error: ${e.message}")
                handleDisconnect()
            }
        }
    }

    private fun readCommandMessage(input: InputStream): ByteArray? {
        return try {
            val size = readVarintFrom(input)
            if (size <= 0) return null
            val data = ByteArray(size)
            var read = 0
            while (read < size) {
                val n = input.read(data, read, size - read)
                if (n <= 0) return null
                read += n
            }
            data
        } catch (e: Exception) {
            Log.w(TAG, "readCommandMessage error: ${e.message}")
            null
        }
    }

    private fun handleRemoteMessage(data: ByteArray) {
        if (data.isEmpty()) return

        // Parse the top-level field number from the first tag
        val parsed = parseTag(data, 0)
        if (parsed == null) return
        val fieldNum = parsed.first
        val wireType = parsed.second

        Log.d(TAG, "Received message: field=$fieldNum wireType=$wireType size=${data.size}")

        when (fieldNum) {
            1 -> {
                // remote_configure - server config (already handled in startReader, but may come again)
                Log.d(TAG, "Got remote_configure")
            }
            2 -> {
                // remote_set_active - respond with our active features
                Log.d(TAG, "Got remote_set_active, responding")
                val resp = pbBytes(2, pbVarint(1, ACTIVE_FEATURES))
                sendRemoteMessage(resp)
            }
            3 -> {
                // remote_error
                Log.e(TAG, "Server sent remote_error")
            }
            8 -> {
                // remote_ping_request - respond with pong (field 9 = remote_ping_response)
                try {
                    val inner = extractFieldBytes(data, 8)
                    val val1 = if (inner != null) extractVarintField(inner, 1) else 0
                    Log.d(TAG, "Ping request val1=$val1, sending pong")
                    val pong = pbBytes(9, pbVarint(1, val1))
                    sendRemoteMessage(pong)
                } catch (_: Exception) {
                    sendRemoteMessage(pbBytes(9, pbVarint(1, 0)))
                }
            }
            9 -> {
                // remote_ping_response (shouldn't come from server, but ignore)
                Log.d(TAG, "Got ping response (ignoring)")
            }
            40 -> {
                // remote_start - connection is fully established
                val inner = extractFieldBytes(data, 40)
                val started = if (inner != null) extractVarintField(inner, 1) else 0
                Log.d(TAG, "Got remote_start: started=$started")
            }
            50 -> {
                // remote_set_volume_level
                try {
                    val inner = extractFieldBytes(data, 50)
                    if (inner != null) {
                        val max = extractVarintField(inner, 6)
                        val level = extractVarintField(inner, 7)
                        Log.d(TAG, "Volume: $level / $max")
                        scope.launch(Dispatchers.Main) { listener?.onVolumeChanged(level, max) }
                    }
                } catch (_: Exception) {}
            }
            else -> {
                Log.d(TAG, "Unhandled message field=$fieldNum, ${data.size} bytes")
            }
        }
    }

    /** Parse a protobuf tag at the given position. Returns (fieldNumber, wireType) and advances. */
    private fun parseTag(data: ByteArray, startPos: Int): Pair<Int, Int>? {
        if (startPos >= data.size) return null
        var pos = startPos
        var tag = 0
        var shift = 0
        while (pos < data.size) {
            val b = data[pos].toInt() and 0xFF
            pos++
            tag = tag or ((b and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
            if (shift >= 35) return null
        }
        return Pair(tag ushr 3, tag and 0x07)
    }

    private fun extractFieldBytes(data: ByteArray, fieldNum: Int): ByteArray? {
        var pos = 0
        while (pos < data.size) {
            // Read tag as varint
            var tag = 0; var shift = 0
            while (pos < data.size) {
                val b = data[pos].toInt() and 0xFF; pos++
                tag = tag or ((b and 0x7F) shl shift)
                if (b and 0x80 == 0) break
                shift += 7
            }
            val fNum = tag ushr 3
            val wireType = tag and 0x07

            when (wireType) {
                2 -> { // length-delimited
                    // Read length as varint
                    var len = 0; shift = 0
                    while (pos < data.size) {
                        val b = data[pos].toInt() and 0xFF; pos++
                        len = len or ((b and 0x7F) shl shift)
                        if (b and 0x80 == 0) break
                        shift += 7
                    }
                    if (fNum == fieldNum) {
                        return data.copyOfRange(pos, minOf(pos + len, data.size))
                    }
                    pos += len
                }
                0 -> { // varint
                    while (pos < data.size && data[pos].toInt() and 0x80 != 0) pos++
                    pos++ // skip last byte of varint
                }
                1 -> pos += 8 // 64-bit
                5 -> pos += 4 // 32-bit
                else -> return null // unknown wire type
            }
        }
        return null
    }

    private fun extractVarintField(data: ByteArray, fieldNum: Int): Int {
        var pos = 0
        while (pos < data.size) {
            // Read tag as varint
            var tag = 0; var shift = 0
            while (pos < data.size) {
                val b = data[pos].toInt() and 0xFF; pos++
                tag = tag or ((b and 0x7F) shl shift)
                if (b and 0x80 == 0) break
                shift += 7
            }
            val fNum = tag ushr 3
            val wireType = tag and 0x07

            when (wireType) {
                0 -> { // varint
                    var result = 0; shift = 0
                    while (pos < data.size) {
                        val b = data[pos].toInt() and 0xFF; pos++
                        result = result or ((b and 0x7F) shl shift)
                        if (b and 0x80 == 0) break
                        shift += 7
                    }
                    if (fNum == fieldNum) return result
                }
                2 -> { // length-delimited
                    var len = 0; shift = 0
                    while (pos < data.size) {
                        val b = data[pos].toInt() and 0xFF; pos++
                        len = len or ((b and 0x7F) shl shift)
                        if (b and 0x80 == 0) break
                        shift += 7
                    }
                    pos += len
                }
                1 -> pos += 8 // 64-bit
                5 -> pos += 4 // 32-bit
                else -> return 0
            }
        }
        return 0
    }

    private fun handleDisconnect() {
        if (!isConnected) return
        isConnected = false
        readerJob?.cancel()
        try { commandSocket?.close() } catch (_: Exception) {}
        commandSocket = null; commandOut = null; commandIn = null
        // Auto-reconnect if we have a saved host and user didn't explicitly disconnect
        if (serverHost.isNotEmpty() && !userDisconnected) {
            Log.d(TAG, "Connection lost, scheduling auto-reconnect to $serverHost")
            scheduleReconnect(serverHost)
        } else {
            scope.launch(Dispatchers.Main) { listener?.onDisconnected() }
        }
    }

    // ===================== Wake-on-LAN =====================

    /** Try to wake the streamer via Wake-on-LAN magic packet */
    fun sendWakeOnLan() {
        val host = serverHost.ifEmpty { prefs.getString("last_host", null) ?: return }
        val macStr = prefs.getString("device_mac", null)

        scope.launch {
            try {
                if (macStr != null) {
                    // We have a stored MAC - send WOL magic packet
                    sendMagicPacket(macStr, host)
                    Log.d(TAG, "Sent WOL magic packet to $macStr")
                    withContext(Dispatchers.Main) {
                        listener?.onError("Sending wake-up signal...")
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        listener?.onError("Cannot wake - no MAC address stored. Connect once while the streamer is on.")
                    }
                }
                // After sending WOL, try to reconnect
                delay(3000)
                if (!isConnected) {
                    connect(host)
                }
            } catch (e: Exception) {
                Log.e(TAG, "WOL failed", e)
            }
        }
    }

    /** Discover and store MAC address from ARP table when connected */
    private fun discoverAndStoreMac(host: String) {
        try {
            // Read ARP table to find MAC for the connected host
            val proc = Runtime.getRuntime().exec("cat /proc/net/arp")
            val reader = proc.inputStream.bufferedReader()
            val lines = reader.readLines()
            reader.close()
            for (line in lines) {
                if (line.contains(host)) {
                    val parts = line.trim().split("\\s+".toRegex())
                    if (parts.size >= 4) {
                        val mac = parts[3].uppercase()
                        if (mac.length == 17 && mac != "00:00:00:00:00:00") {
                            prefs.edit().putString("device_mac", mac).apply()
                            Log.d(TAG, "Stored MAC address: $mac for $host")
                            return
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "MAC discovery failed: ${e.message}")
        }
    }

    private fun sendMagicPacket(macStr: String, host: String) {
        val macBytes = macStr.split(":").map { it.toInt(16).toByte() }.toByteArray()
        if (macBytes.size != 6) return

        // Magic packet: 6 bytes of 0xFF followed by MAC address repeated 16 times
        val packet = ByteArray(6 + 16 * 6)
        for (i in 0..5) packet[i] = 0xFF.toByte()
        for (i in 0..15) System.arraycopy(macBytes, 0, packet, 6 + i * 6, 6)

        // Send to broadcast address on port 9
        val broadcastAddr = try {
            // Derive broadcast from host IP (assume /24 subnet)
            val parts = host.split(".")
            if (parts.size == 4) {
                java.net.InetAddress.getByName("${parts[0]}.${parts[1]}.${parts[2]}.255")
            } else {
                java.net.InetAddress.getByName("255.255.255.255")
            }
        } catch (e: Exception) {
            java.net.InetAddress.getByName("255.255.255.255")
        }

        val dgPacket = java.net.DatagramPacket(packet, packet.size, broadcastAddr, 9)
        val socket = java.net.DatagramSocket()
        socket.broadcast = true
        socket.send(dgPacket)
        socket.close()

        // Also send directly to the host IP
        try {
            val directPacket = java.net.DatagramPacket(packet, packet.size, java.net.InetAddress.getByName(host), 9)
            val socket2 = java.net.DatagramSocket()
            socket2.send(directPacket)
            socket2.close()
        } catch (_: Exception) {}
    }

    // ===================== Protobuf helpers =====================

    private fun pbVarint(field: Int, value: Int): ByteArray {
        val out = ByteArrayOutputStream()
        writeVarintTo(out, (field shl 3) or 0)
        writeVarintTo(out, value)
        return out.toByteArray()
    }

    private fun pbString(field: Int, value: String) = pbBytes(field, value.toByteArray(Charsets.UTF_8))

    private fun pbBytes(field: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        writeVarintTo(out, (field shl 3) or 2)
        writeVarintTo(out, value.size)
        out.write(value)
        return out.toByteArray()
    }

    private fun writeVarintTo(out: OutputStream, value: Int) {
        var v = value
        while (v > 0x7F) { out.write((v and 0x7F) or 0x80); v = v ushr 7 }
        out.write(v and 0x7F)
    }

    private fun readVarintFrom(input: InputStream): Int {
        var result = 0; var shift = 0
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
        userDisconnected = true
        isConnected = false; isPaired = false
        readerJob?.cancel()
        reconnectJob?.cancel()
        try { commandSocket?.close() } catch (_: Exception) {}
        closePairing()
        commandSocket = null; commandOut = null; commandIn = null
    }

    fun destroy() { disconnect(); scope.cancel() }
}
