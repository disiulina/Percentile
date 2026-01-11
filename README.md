# ARP Spoofing Detection berbasis Entropi & Percentile (OpenWRT)

Code lengkap sistem deteksi ARP Spoofing yang berjalan langsung di router berbasis OpenWRT, sesuai dengan flowchart penelitian pada. Sistem tidak hanya melakukan perhitungan percentile, tetapi mencakup monitoring ARP packet, perhitungan entropi, penentuan threshold (P10), pengecekan duplikasi IP–MAC, hingga logging dan validasi serangan.

## 🛠️ Teknologi yang Digunakan

Operating System: OpenWRT

Bahasa Pemrograman: Lua

Library: Lua (tanpa library eksternal)

## 📦 Requirement Sistem (OpenWRT)

opkg update

opkg install lua
