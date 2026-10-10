# Projenin sözleşmesi: collector.py çıktısına göre hazırlandı.
# Sözlük değişirse sadece bu dosya güncellenir.

# --- Blok A: sayısal özellikler (collector'ın "numeric" alanındaki isimler) ---
SAYISAL_OZELLIKLER = [
    "cpu_percent",
    "ram_percent",
    "threads",
    "disk_bytes_per_sec",
    "remote_conn_count",
    "listen_port_count",
    "age_seconds",
]

# --- Blok B: Bag-of-Words sözlüğü (var = 1, yok = 0) ---
KONUM_KELIMELERI = ["loc_system", "loc_windowsapps", "loc_programfiles",
                    "loc_temp", "loc_appdata", "loc_downloads", "loc_public"]
IMZA_KELIMELERI = ["sig_signed", "sig_unsigned", "sig_invalid", "sig_packaged"]
PORT_KELIMELERI = ["port_80", "port_443", "port_3333", "port_4444"]
CMD_KELIMELERI = ["cmd_stratum", "cmd_pool", "cmd_hidden", "cmd_enc"]

# DLL'ler şimdilik boş. Gerçek out.json verisine bakıp ayırt edici 5-10 tanesini seç.
# Örnek: ["dll_wininet.dll", "dll_ws2_32.dll"]  (collector DLL adlarına "dll_" ekler)
DLL_KELIMELERI = []

KELIMELER = (KONUM_KELIMELERI + IMZA_KELIMELERI + PORT_KELIMELERI
             + CMD_KELIMELERI + DLL_KELIMELERI)

# --- Blok ağırlıkları (Atallah'ın önerisi: kelimeler daha belirleyici) ---
AGIRLIK_A = 0.4   # sayısal blok
AGIRLIK_B = 0.6   # kelime bloğu

# --- Risk kuralları ---
RISKLI_KONUMLAR = ["loc_temp", "loc_appdata", "loc_downloads"]
