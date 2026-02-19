package com.gotvremote.app

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.view.View
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity(), AndroidTvRemote.Listener {

    private lateinit var remote: AndroidTvRemote
    private lateinit var tvStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        remote = AndroidTvRemote(this)
        remote.listener = this

        tvStatus = findViewById(R.id.tvConnectionStatus)
        updateStatus("Disconnected", R.color.accent_red)

        setupButtons()

        // Auto-connect to last known host
        val lastHost = remote.getLastHost()
        if (lastHost != null) {
            updateStatus("Connecting...", R.color.accent_yellow)
            remote.connect(lastHost)
        } else {
            showConnectDialog()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        remote.destroy()
    }

    // ===================== Connection UI =====================

    private fun showConnectDialog() {
        val input = EditText(this).apply {
            hint = "e.g. 192.168.1.100"
            setText(remote.getLastHost() ?: "")
            setPadding(48, 32, 48, 32)
            setTextColor(0xFF000000.toInt())
            setHintTextColor(0xFF888888.toInt())
            setBackgroundColor(0xFFEEEEEE.toInt())
        }

        AlertDialog.Builder(this)
            .setTitle("Connect to GOtv")
            .setMessage("Enter the IP address of your GOtv streamer.\n\nFind it in: GOtv Settings > Network > IP address")
            .setView(input)
            .setPositiveButton("Connect") { _, _ ->
                val host = input.text.toString().trim()
                if (host.isNotEmpty()) {
                    updateStatus("Connecting...", R.color.accent_yellow)
                    remote.connect(host)
                }
            }
            .setNegativeButton("Cancel", null)
            .setCancelable(false)
            .show()
    }

    private fun showPairingDialog(message: String?) {
        val input = EditText(this).apply {
            hint = "e.g. A1B2C3"
            setPadding(48, 32, 48, 32)
            setTextColor(0xFF000000.toInt())
            setHintTextColor(0xFF888888.toInt())
            setBackgroundColor(0xFFEEEEEE.toInt())
            textSize = 24f
            textAlignment = View.TEXT_ALIGNMENT_CENTER
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS
        }

        AlertDialog.Builder(this)
            .setTitle("Pair with GOtv")
            .setMessage(message ?: "Enter the 6-character code shown on your TV screen")
            .setView(input)
            .setPositiveButton("Pair") { _, _ ->
                val code = input.text.toString().trim()
                if (code.isNotEmpty()) {
                    updateStatus("Pairing...", R.color.accent_yellow)
                    remote.submitPairingCode(code)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun updateStatus(text: String, colorRes: Int) {
        tvStatus.text = text
        tvStatus.setTextColor(getColor(colorRes))
    }

    // ===================== AndroidTvRemote.Listener =====================

    override fun onConnected() {
        updateStatus("Connected", R.color.accent_green)
        Toast.makeText(this, "Connected to GOtv!", Toast.LENGTH_SHORT).show()
    }

    override fun onDisconnected() {
        updateStatus("Disconnected", R.color.accent_red)
    }

    override fun onPairingRequired(pairingCode: String?) {
        updateStatus("Pairing needed", R.color.accent_yellow)
        showPairingDialog(pairingCode)
    }

    override fun onPairingComplete() {
        Toast.makeText(this, "Pairing successful!", Toast.LENGTH_SHORT).show()
    }

    override fun onError(message: String) {
        updateStatus("Error", R.color.accent_red)
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    override fun onVolumeChanged(volume: Int, max: Int) {
        // Could update a volume indicator in the UI
    }

    // ===================== Button Setup =====================

    private fun setupButtons() {
        // Settings
        findViewById<ImageButton>(R.id.btnSettings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        // Long press settings = reconnect
        findViewById<ImageButton>(R.id.btnSettings).setOnLongClickListener {
            showConnectDialog()
            true
        }

        // Power row
        mapButton(R.id.btnPower, "POWER")
        mapButton(R.id.btnInput, "INPUT")
        mapButton(R.id.btnMute, "MUTE")

        // Number pad
        mapButton(R.id.btn0, "0")
        mapButton(R.id.btn1, "1")
        mapButton(R.id.btn2, "2")
        mapButton(R.id.btn3, "3")
        mapButton(R.id.btn4, "4")
        mapButton(R.id.btn5, "5")
        mapButton(R.id.btn6, "6")
        mapButton(R.id.btn7, "7")
        mapButton(R.id.btn8, "8")
        mapButton(R.id.btn9, "9")
        mapButton(R.id.btnLast, "LAST")
        mapButton(R.id.btnGuide, "GUIDE")

        // D-Pad
        mapButton(R.id.btnUp, "UP")
        mapButton(R.id.btnDown, "DOWN")
        mapButton(R.id.btnLeft, "LEFT")
        mapButton(R.id.btnRight, "RIGHT")
        mapButton(R.id.btnOk, "OK")

        // Volume & Channel
        mapButton(R.id.btnVolUp, "VOL_UP")
        mapButton(R.id.btnVolDown, "VOL_DOWN")
        mapButton(R.id.btnChUp, "CH_UP")
        mapButton(R.id.btnChDown, "CH_DOWN")

        // Function buttons
        mapButton(R.id.btnMenu, "MENU")
        mapButton(R.id.btnHome, "HOME")
        mapButton(R.id.btnBack, "BACK")
        mapButton(R.id.btnInfo, "INFO")

        // Extra functions
        mapButton(R.id.btnEpg, "EPG")
        mapButton(R.id.btnFav, "FAV")
        mapButton(R.id.btnSubtitle, "SUBTITLE")
        mapButton(R.id.btnAudio, "AUDIO")

        // Media controls
        mapButton(R.id.btnPlayPause, "PLAY_PAUSE")
        mapButton(R.id.btnStop, "STOP")
        mapButton(R.id.btnRecord, "RECORD")
        mapButton(R.id.btnRewind, "REWIND")
        mapButton(R.id.btnFastForward, "FAST_FORWARD")
    }

    private fun mapButton(viewId: Int, command: String) {
        findViewById<View>(viewId).setOnClickListener {
            hapticFeedback()
            if (remote.isConnected) {
                remote.sendCommand(command)
            } else {
                Toast.makeText(this, "Not connected. Tap settings to connect.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun hapticFeedback() {
        try {
            val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vm = getSystemService(VIBRATOR_MANAGER_SERVICE) as VibratorManager
                vm.defaultVibrator
            } else {
                @Suppress("DEPRECATION")
                getSystemService(VIBRATOR_SERVICE) as Vibrator
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                vibrator.vibrate(VibrationEffect.createOneShot(25, VibrationEffect.DEFAULT_AMPLITUDE))
            } else {
                @Suppress("DEPRECATION")
                vibrator.vibrate(25)
            }
        } catch (_: Exception) {}
    }
}
