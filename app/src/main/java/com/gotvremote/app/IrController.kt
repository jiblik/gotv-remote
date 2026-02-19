package com.gotvremote.app

import android.content.Context
import android.hardware.ConsumerIrManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager

/**
 * IR Controller for GOtv set-top box.
 * Uses NEC protocol (38kHz carrier frequency).
 *
 * GOtv boxes typically use NEC IR protocol with specific device codes.
 * The ASUS Zenfone 10 has a built-in IR blaster which makes it perfect
 * for this use case.
 */
class IrController(private val context: Context) {

    private val irManager: ConsumerIrManager? =
        context.getSystemService(Context.CONSUMER_IR_SERVICE) as? ConsumerIrManager

    private val vibrator: Vibrator by lazy {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val vm = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager
            vm.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            context.getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
        }
    }

    val hasIrBlaster: Boolean
        get() = irManager?.hasIrEmitter() == true

    companion object {
        private const val NEC_FREQ = 38000 // 38kHz carrier for NEC protocol

        // NEC timing constants (in microseconds)
        private const val NEC_HDR_MARK = 9000
        private const val NEC_HDR_SPACE = 4500
        private const val NEC_BIT_MARK = 562
        private const val NEC_ONE_SPACE = 1687
        private const val NEC_ZERO_SPACE = 562
        private const val NEC_STOP_BIT = 562

        // GOtv decoder IR codes (NEC protocol)
        // Device address: 0x04 (common for GOtv/StarTimes decoders)
        private const val DEVICE_ADDR: Int = 0x04

        // Command codes for GOtv decoder
        val IR_CODES = mapOf(
            "POWER" to 0x08,
            "MUTE" to 0x0A,
            "INPUT" to 0x0B,
            "0" to 0x00,
            "1" to 0x01,
            "2" to 0x02,
            "3" to 0x03,
            "4" to 0x04,
            "5" to 0x05,
            "6" to 0x06,
            "7" to 0x07,
            "8" to 0x08,
            "9" to 0x09,
            "OK" to 0x1C,
            "UP" to 0x10,
            "DOWN" to 0x11,
            "LEFT" to 0x15,
            "RIGHT" to 0x16,
            "MENU" to 0x12,
            "BACK" to 0x13,
            "HOME" to 0x14,
            "GUIDE" to 0x0D,
            "EPG" to 0x0E,
            "INFO" to 0x0F,
            "VOL_UP" to 0x1A,
            "VOL_DOWN" to 0x1B,
            "CH_UP" to 0x18,
            "CH_DOWN" to 0x19,
            "FAV" to 0x0C,
            "LAST" to 0x17,
            "SUBTITLE" to 0x20,
            "AUDIO" to 0x21,
            "PLAY_PAUSE" to 0x30,
            "STOP" to 0x31,
            "RECORD" to 0x32,
            "REWIND" to 0x33,
            "FAST_FORWARD" to 0x34
        )
    }

    /**
     * Encode a NEC protocol IR pattern.
     * NEC format: Leader + Address + ~Address + Command + ~Command + Stop
     */
    private fun encodeNec(address: Int, command: Int): IntArray {
        val pattern = mutableListOf<Int>()

        // Leader code
        pattern.add(NEC_HDR_MARK)
        pattern.add(NEC_HDR_SPACE)

        // Address byte (LSB first)
        for (i in 0 until 8) {
            pattern.add(NEC_BIT_MARK)
            if ((address shr i) and 1 == 1) {
                pattern.add(NEC_ONE_SPACE)
            } else {
                pattern.add(NEC_ZERO_SPACE)
            }
        }

        // Inverted address byte (LSB first)
        val invAddress = address.inv() and 0xFF
        for (i in 0 until 8) {
            pattern.add(NEC_BIT_MARK)
            if ((invAddress shr i) and 1 == 1) {
                pattern.add(NEC_ONE_SPACE)
            } else {
                pattern.add(NEC_ZERO_SPACE)
            }
        }

        // Command byte (LSB first)
        for (i in 0 until 8) {
            pattern.add(NEC_BIT_MARK)
            if ((command shr i) and 1 == 1) {
                pattern.add(NEC_ONE_SPACE)
            } else {
                pattern.add(NEC_ZERO_SPACE)
            }
        }

        // Inverted command byte (LSB first)
        val invCommand = command.inv() and 0xFF
        for (i in 0 until 8) {
            pattern.add(NEC_BIT_MARK)
            if ((invCommand shr i) and 1 == 1) {
                pattern.add(NEC_ONE_SPACE)
            } else {
                pattern.add(NEC_ZERO_SPACE)
            }
        }

        // Stop bit
        pattern.add(NEC_STOP_BIT)

        return pattern.toIntArray()
    }

    /**
     * Send an IR command for the given button name.
     * Returns true if the command was sent successfully.
     */
    fun sendCommand(buttonName: String): Boolean {
        val commandCode = IR_CODES[buttonName] ?: return false
        return transmit(DEVICE_ADDR, commandCode)
    }

    /**
     * Send a raw NEC IR command with given address and command.
     */
    fun transmit(address: Int, command: Int): Boolean {
        hapticFeedback()

        val irManager = this.irManager ?: return false
        if (!irManager.hasIrEmitter()) return false

        return try {
            val pattern = encodeNec(address, command)
            irManager.transmit(NEC_FREQ, pattern)
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    private fun hapticFeedback() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                vibrator.vibrate(VibrationEffect.createOneShot(30, VibrationEffect.DEFAULT_AMPLITUDE))
            } else {
                @Suppress("DEPRECATION")
                vibrator.vibrate(30)
            }
        } catch (_: Exception) {}
    }
}
