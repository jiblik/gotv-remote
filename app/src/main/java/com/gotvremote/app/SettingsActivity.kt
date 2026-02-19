package com.gotvremote.app

import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class SettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val prefs = getSharedPreferences("atv_remote", MODE_PRIVATE)
        val lastHost = prefs.getString("last_host", "Not set")

        // Connection Status
        findViewById<TextView>(R.id.tvIrStatus).text = buildString {
            append("Connection: WiFi (Android TV Remote Protocol v2)\n")
            append("Last connected to: $lastHost\n")
            append("Port: 6466 (commands) / 6467 (pairing)")
        }

        // Device Info
        findViewById<TextView>(R.id.tvDeviceInfo).text = buildString {
            append("Phone: ${Build.MANUFACTURER} ${Build.MODEL}\n")
            append("Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})\n")
            append("Device: ${Build.DEVICE}")
        }

        // Test button
        findViewById<Button>(R.id.btnTestIr).text = "Forget Pairing & Reconnect"
        findViewById<Button>(R.id.btnTestIr).setOnClickListener {
            // Clear saved certificate to force re-pairing
            val certFile = java.io.File(filesDir, "atv_keystore.bks")
            if (certFile.exists()) certFile.delete()
            prefs.edit().remove("last_host").apply()
            Toast.makeText(this, "Pairing data cleared. Reopen the app to reconnect.", Toast.LENGTH_LONG).show()
        }
    }
}
