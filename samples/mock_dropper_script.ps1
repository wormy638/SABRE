#!/usr/bin/env pwsh
# HARMLESS ATMDE-NATIVE STATIC ANALYSIS TEST FILE
# This file contains inert RFC 5737 / RFC 2606 strings for testing IOC extraction.

$TestC2Server = "203.0.113.199"
$TestDomain   = "dropper-sim.example.org"
$TestUri      = "/stage2/config.dat?token=demo_test"
$TestRegKey   = "HKLM\SYSTEM\CurrentControlSet\Services\MockTestService\ImagePath"
$TestMutex    = "BaseNamedObjects\MockDropperTestMutex"
Write-Output "Benign test sample for ATMDE-Native static analysis."