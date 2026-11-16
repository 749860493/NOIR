/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.core

/**
 * Package and upload-host rules that keep known-safe entries out of a scan.
 *
 * The file format is deliberately small:
 *  - `package com.example.app` (or a bare package name)
 *  - `host example.com` (subdomains match; `*.example.com` is accepted)
 *  - blank lines and `#` comments are ignored
 */
data class IgnoreRules(
    val packages: Set<String> = emptySet(),
    val hosts: Set<String> = emptySet()
) {
    val isEmpty: Boolean get() = packages.isEmpty() && hosts.isEmpty()

    fun ignoresPackage(pkg: String): Boolean = pkg in packages

    fun ignoresHost(host: String): Boolean {
        val value = host.trim().trimEnd('.').lowercase()
        if (value.isEmpty()) return false
        return hosts.any { value == it || value.endsWith(".$it") }
    }

    fun filterEndpoints(endpoints: List<String>): List<String> {
        if (hosts.isEmpty()) return endpoints
        return endpoints.filterNot { endpoint ->
            val host = Exposure.hostOf(endpoint)
            host != null && ignoresHost(host)
        }
    }

    /** Stable representation written next to a report so the filter is reproducible. */
    fun render(): String = buildString {
        appendLine("# NOIR ignore rules")
        packages.forEach { appendLine("package $it") }
        hosts.forEach { appendLine("host $it") }
    }

    companion object {
        val EMPTY = IgnoreRules()

        fun parse(lines: Sequence<String>): IgnoreRules {
            val packages = LinkedHashSet<String>()
            val hosts = LinkedHashSet<String>()
            lines.forEach { raw ->
                val line = raw.substringBefore('#').trim()
                if (line.isEmpty()) return@forEach
                when {
                    line.startsWith("package ") ->
                        packages += line.removePrefix("package ").trim()
                    line.startsWith("package:") ->
                        packages += line.removePrefix("package:").trim()
                    line.startsWith("pkg ") ->
                        packages += line.removePrefix("pkg ").trim()
                    line.startsWith("pkg:") ->
                        packages += line.removePrefix("pkg:").trim()
                    line.startsWith("host ") ->
                        normalizeHost(line.removePrefix("host "))?.let(hosts::add)
                    line.startsWith("host:") ->
                        normalizeHost(line.removePrefix("host:"))?.let(hosts::add)
                    line.startsWith("domain ") ->
                        normalizeHost(line.removePrefix("domain "))?.let(hosts::add)
                    line.startsWith("domain:") ->
                        normalizeHost(line.removePrefix("domain:"))?.let(hosts::add)
                    else -> packages += line
                }
            }
            return IgnoreRules(packages, hosts)
        }

        private fun normalizeHost(value: String): String? =
            value.trim()
                .removePrefix("*.")
                .trimStart('.')
                .trimEnd('.')
                .lowercase()
                .takeIf { it.isNotEmpty() && it.contains('.') }
    }
}
