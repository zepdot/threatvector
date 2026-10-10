from core.vectorizer import profil_vektoru

# Başlangıç değerleri: Atallah'ın kılavuzundaki tablo.
# Erkam'ın simülasyon ölçümlerine göre ayarlanacak.
# NOT: loc_temp ve loc_appdata ikisi de verildi çünkü bir süreç ikisinden birinde olur.
# NOT: cmd_pool / cmd_hidden / cmd_enc tabloda yoktu, sözlükte olduğu için sonradan eklendi.
PROFILLER = {
    "normal": profil_vektoru(
        sayisal={"cpu_percent": 0.10, "ram_percent": 0.10, "threads": 0.40,
                 "disk_bytes_per_sec": 0.30, "remote_conn_count": 0.20,
                 "age_seconds": 0.30},
        kelimeler=["sig_signed", "loc_programfiles", "port_443"]),
    "spyware": profil_vektoru(
        sayisal={"cpu_percent": 0.05, "ram_percent": 0.05, "threads": 0.20,
                 "disk_bytes_per_sec": 0.30, "remote_conn_count": 0.15,
                 "age_seconds": 0.70},
        kelimeler=["sig_unsigned", "loc_appdata", "loc_temp", "port_443",
                   "cmd_hidden", "cmd_enc"]),
    "cryptominer": profil_vektoru(
        sayisal={"cpu_percent": 0.90, "ram_percent": 0.10, "threads": 0.40,
                 "disk_bytes_per_sec": 0.05, "remote_conn_count": 0.10,
                 "age_seconds": 0.70},
        kelimeler=["sig_unsigned", "loc_appdata", "loc_temp", "port_3333",
                   "cmd_stratum", "cmd_pool"]),
}
