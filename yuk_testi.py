import multiprocessing as m

def dongu():
    while True:
        pass

if __name__ == "__main__":
    for _ in range(m.cpu_count()):
        m.Process(target=dongu, daemon=True).start()
    input("Tum cekirdekler yoruluyor. Durdurmak icin Enter'a bas...")