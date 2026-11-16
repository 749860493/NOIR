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
import app.noir.core.ReportMeta
import app.noir.core.localized
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File

internal data class FullReport(
    val device: Device,
    val meta: ReportMeta,
    val apps: List<AppEntry>,
    val recommendations: List<Recommendation>
)

/** Reads the complete report.json shape, for re-rendering without a device scan. */
internal fun readFullReport(path: String): FullReport {
    val file = File(path)
    require(file.isFile) { "report not found: ${file.path}" }
    val root = JsonParser.parseString(file.readText()).asJsonObject
    val env = root.get("environment")?.takeIf { it.isJsonObject }?.asJsonObject
        ?: error("invalid report: missing environment object")
    val device = root.get("device")?.takeIf { it.isJsonObject }?.asJsonObject
        ?: error("invalid report: missing device object")
    val appsJson = root.get("apps")?.takeIf { it.isJsonArray }?.asJsonArray
        ?: error("invalid report: missing apps array")

    val apps = appsJson.map { element ->
        require(element.isJsonObject) { "invalid report: app entry is not an object" }
        val app = element.asJsonObject
        val pkg = app.string("package")
        require(pkg.isNotBlank()) { "invalid report: app entry has no package" }
        AppEntry(
            pkg = pkg,
            uid = app.string("uid"),
            isSystem = app.bool("system"),
            debuggable = app.bool("debuggable"),
            installer = app.stringOrNull("installer"),
            permissions = app.strings("permissions"),
            endpoints = app.strings("endpoints"),
            score = app.int("score") ?: 0,
            category = categoryOf(app.string("categoryKey"), app.string("category")),
            vendor = app.stringOrNull("vendor"),
            sharedUid = app.stringOrNull("sharedUid")
        )
    }

    val recommendations = root.get("recommendations")
        ?.takeIf { it.isJsonArray }
        ?.asJsonArray
        ?.mapNotNull { element ->
            if (!element.isJsonObject) return@mapNotNull null
            val rec = element.asJsonObject
            val pkg = rec.string("package")
            if (pkg.isBlank()) return@mapNotNull null
            Recommendation(
                pkg = pkg,
                action = actionOf(rec.string("actionKey"), rec.string("action")),
                risk = rec.string("risk", "LOW"),
                reason = rec.string("reason"),
                autoSafe = rec.bool("autoSafe")
            )
        }
        ?: emptyList()

    return FullReport(
        device = Device(
            serial = device.string("serial"),
            state = "device",
            model = device.string("model"),
            product = device.string("product")
        ),
        meta = ReportMeta(
            tool = env.string("tool"),
            host = env.string("host"),
            android = env.string("android"),
            sdk = env.string("sdk"),
            build = env.string("build"),
            fingerprint = env.string("fingerprint"),
            user = env.string("user"),
            generatedAt = env.string("generatedAt"),
            minScore = env.int("minScore"),
            limit = env.int("limit")
        ),
        apps = apps,
        recommendations = recommendations
    )
}

private fun categoryOf(key: String, label: String): Category {
    Category.entries.firstOrNull { it.name == key }?.let { return it }
    return Category.entries.firstOrNull {
        it.localized(Lang.ZH) == label || it.localized(Lang.EN).equals(label, ignoreCase = true)
    } ?: Category.OTHER
}

private fun actionOf(key: String, label: String): ActionType {
    ActionType.entries.firstOrNull { it.name == key }?.let { return it }
    return ActionType.entries.firstOrNull { it.label == label } ?: ActionType.REVIEW
}

private fun JsonObject.string(key: String, fallback: String = ""): String =
    get(key)?.takeIf { !it.isJsonNull }?.asString ?: fallback

private fun JsonObject.stringOrNull(key: String): String? =
    get(key)?.takeIf { !it.isJsonNull }?.asString

private fun JsonObject.int(key: String): Int? =
    get(key)?.takeIf { !it.isJsonNull }?.asInt

private fun JsonObject.bool(key: String, fallback: Boolean = false): Boolean =
    get(key)?.takeIf { !it.isJsonNull }?.asBoolean ?: fallback

private fun JsonObject.strings(key: String): List<String> {
    val value = get(key) ?: return emptyList()
    require(value.isJsonArray) { "invalid report: $key must be an array" }
    return value.asJsonArray.map { element ->
        require(element.isJsonPrimitive && element.asJsonPrimitive.isString) {
            "invalid report: $key must contain strings"
        }
        element.asString
    }
}
