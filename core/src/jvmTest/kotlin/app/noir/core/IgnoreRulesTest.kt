/*
 * NOIR — Android leak audit
 * Copyright (c) 2026 Verlintas
 * SPDX-License-Identifier: MIT
 */
package app.noir.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class IgnoreRulesTest {

    @Test
    fun `parses packages hosts and comments`() {
        val rules = IgnoreRules.parse(
            sequenceOf(
                "# known-safe entries",
                "",
                "com.example.known",
                "package com.example.other",
                "pkg com.example.third",
                "host example.com",
                "domain:*.tracker.test",
                "host sub.example.net"
            )
        )

        assertTrue(rules.ignoresPackage("com.example.known"))
        assertTrue(rules.ignoresPackage("com.example.other"))
        assertTrue(rules.ignoresPackage("com.example.third"))
        assertFalse(rules.ignoresPackage("com.example.unknown"))

        assertTrue(rules.ignoresHost("example.com"))
        assertTrue(rules.ignoresHost("api.example.com"))
        assertTrue(rules.ignoresHost("tracker.test"))
        assertTrue(rules.ignoresHost("a.b.tracker.test"))
        assertFalse(rules.ignoresHost("notexample.com"))
        assertFalse(rules.ignoresHost("example.com.evil"))
    }

    @Test
    fun `filters endpoints by host suffix`() {
        val rules = IgnoreRules.parse(
            sequenceOf(
                "host example.com",
                "host tracker.test"
            )
        )
        val endpoints = listOf(
            "https://api.example.com/v1/collect",
            "https://tracker.test/pixel",
            "https://other.test/path",
            "http://10.0.0.1:8080/collect"
        )

        assertEquals(
            listOf("https://other.test/path", "http://10.0.0.1:8080/collect"),
            rules.filterEndpoints(endpoints)
        )
    }

    @Test
    fun `renders a reproducible ignore file`() {
        val text = IgnoreRules.parse(sequenceOf("com.example.app", "host example.com")).render()
        assertTrue(text.contains("package com.example.app"))
        assertTrue(text.contains("host example.com"))
    }

    @Test
    fun `empty rules keep every endpoint`() {
        val endpoints = listOf("https://example.com/a", "https://other.test/b")
        assertEquals(endpoints, IgnoreRules.EMPTY.filterEndpoints(endpoints))
        assertTrue(IgnoreRules.EMPTY.isEmpty)
    }
}
