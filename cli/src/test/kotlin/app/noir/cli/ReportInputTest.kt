/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.cli

import app.noir.core.ActionType
import app.noir.core.AppEntry
import app.noir.core.Category
import app.noir.core.Device
import app.noir.core.Lang
import app.noir.core.Recommendation
import app.noir.core.Report
import app.noir.core.ReportMeta
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReportInputTest {

    @Test
    fun `round trips the full report json shape`() {
        val device = Device("serial", "device", "Pixel", "product")
        val meta = ReportMeta(
            tool = "NOIR test",
            host = "macOS aarch64",
            android = "16",
            sdk = "36",
            build = "PLK110_16",
            fingerprint = "oneplus/PLK110:16/abc",
            user = "0",
            generatedAt = "2026-11-16T00:00:00Z",
            minScore = 10,
            limit = 500
        )
        val app = AppEntry(
            pkg = "com.example.app",
            uid = "10200",
            isSystem = false,
            debuggable = true,
            installer = "com.android.vending",
            permissions = listOf("INTERNET", "READ_SMS"),
            endpoints = listOf("https://example.com/collect"),
            score = 35,
            category = Category.TELEMETRY,
            vendor = "Example",
            sharedUid = "android.uid.system"
        )
        val recommendation = Recommendation(
            pkg = app.pkg,
            action = ActionType.REVIEW,
            risk = "MED",
            reason = "test",
            autoSafe = false
        )
        val file = Files.createTempFile("noir-report-input", ".json").toFile()
        try {
            file.writeText(Report.json(device, listOf(app), listOf(recommendation), meta, Lang.EN))
            val parsed = readFullReport(file.path)

            assertEquals(device.serial, parsed.device.serial)
            assertEquals(device.product, parsed.device.product)
            assertEquals(meta, parsed.meta)
            assertEquals(1, parsed.apps.size)
            assertEquals(app, parsed.apps.single())
            assertEquals(1, parsed.recommendations.size)
            assertEquals(recommendation, parsed.recommendations.single())
            assertTrue(Report.markdown(parsed.device, parsed.apps, parsed.recommendations, parsed.meta, Lang.EN).contains("com.example.app"))
        } finally {
            file.delete()
        }
    }
}
