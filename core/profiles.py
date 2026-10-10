from core.vectorizer import profil_vektoru

PROFILLER = {
    "normal": profil_vektoru(cpu=0.1, ram_mb=0.1, sig_valid=1,
                             loc_programfiles=1, port_443=1),
    "cryptominer": profil_vektoru(cpu=0.95, net_sent=0.3, port_3333=1,
                                  cmd_stratum=1, sig_none=1, loc_temp=1),
    "spyware": profil_vektoru(cpu=0.05, net_sent=0.6, dll_keyboard_hook=1,
                              cmd_hidden=1, sig_none=1, loc_appdata=1),
}