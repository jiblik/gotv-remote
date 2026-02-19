package com.gotvremote.app

import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class SettingsActivity : AppCompatActivity() {

    private lateinit var irController: IrController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        irController = IrController(this)

        // IR Status
        findViewById<TextView>(R.id.tvIrStatus).text = if (irController.hasIrBlaster) {
            "IR Blaster: Available and ready"
        } else {
            "IR Blaster: Not detected on this device.\nThis app requires a phone with an IR blaster (like ASUS Zenfone 10)."
        }

        // Device Info
        findViewById<TextView>(R.id.tvDeviceInfo).text = buildString {
            append("Model: ${Build.MANUFACTURER} ${Build.MODEL}\n")
            append("Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})\n")
            append("Device: ${Build.DEVICE}\n")
            append("IR Blaster: ${if (irController.hasIrBlaster) "Yes" else "No"}")
        }

        // Test button
        findViewById<Button>(R.id.btnTestIr).setOnClickListener {
            if (irController.hasIrBlaster) {
                // Send a harmless "info" command as a test
                val sent = irController.sendCommand("INFO")
                if (sent) {
                    Toast.makeText(this, "IR signal sent! Check if your GOtv responded.", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Failed to send IR signal", Toast.LENGTH_SHORT).show()
                }
            } else {
                Toast.makeText(this, "No IR blaster found on this device", Toast.LENGTH_LONG).show()
            }
        }
    }
}
