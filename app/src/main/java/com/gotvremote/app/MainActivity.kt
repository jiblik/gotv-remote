package com.gotvremote.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var irController: IrController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        irController = IrController(this)
        updateConnectionStatus()
        setupButtons()
    }

    private fun updateConnectionStatus() {
        val tvStatus = findViewById<TextView>(R.id.tvConnectionStatus)
        if (irController.hasIrBlaster) {
            tvStatus.text = "IR Ready"
            tvStatus.setTextColor(getColor(R.color.accent_green))
        } else {
            tvStatus.text = "No IR Blaster"
            tvStatus.setTextColor(getColor(R.color.accent_red))
        }
    }

    private fun setupButtons() {
        // Settings
        findViewById<ImageButton>(R.id.btnSettings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
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
            val sent = irController.sendCommand(command)
            if (!sent && !irController.hasIrBlaster) {
                Toast.makeText(this, "No IR blaster detected on this device", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
