from core.risk import siniflandir, risk_skoru, seviye

sahte_surecler = [
    {"ad": "chrome.exe", "cpu": 8, "ram_mb": 500, "connections": 20,
     "kelimeler": ["loc_programfiles", "sig_valid", "port_443"]},
    {"ad": "miner.exe", "cpu": 92, "ram_mb": 200, "net_sent": 3000,
     "kelimeler": ["loc_temp", "sig_none", "port_3333", "cmd_stratum"]},
    {"ad": "keylog.exe", "cpu": 3, "ram_mb": 50, "net_sent": 6000,
     "kelimeler": ["loc_appdata", "sig_none", "dll_keyboard_hook", "cmd_hidden"]},
    {"ad": "yedekleme.exe", "cpu": 70, "ram_mb": 300, "net_sent": 4000,
     "kelimeler": ["loc_programfiles", "sig_valid", "port_443"]},
    {"ad": "bilinmeyen.exe", "cpu": 40, "ram_mb": 150, "net_sent": 2000,
     "kelimeler": ["loc_temp", "sig_none"]},
]

for s in sahte_surecler:
    profil, skorlar = siniflandir(s)
    risk = risk_skoru(s, skorlar)
    print(f'{s["ad"]:15} -> {profil:12} risk={risk:3} ({seviye(risk)})')