import socket
import json
import random
import time


def is_probable_prime(n: int, k: int = 20) -> bool:
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small:
        return True
    for p in small:
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    def witness(a: int) -> bool:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                return True
        return False
    bases = (
        (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
        if n < (1 << 64)
        else [random.randrange(2, n - 2) for _ in range(k)]
    )
    for a in bases:
        a %= n
        if a and not witness(a):
            return False
    return True


def gerar_primo(bits: int) -> int:
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if is_probable_prime(n):
            return n


def _egcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("Inverso modular inexistente")
    return x % m


def gerar_chaves_rsa(bits: int = 4096):
    half = bits // 2
    print(f"[RSA] Gerando chaves de {bits} bits...")
    t0 = time.perf_counter()
    p = gerar_primo(half)
    q = gerar_primo(half)
    while q == p:
        q = gerar_primo(half)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    print(f"[RSA] Chaves prontas em {time.perf_counter() - t0:.2f}s")
    return (e, n), (d, n)


def rsa_encrypt(msg_int: int, pub: tuple) -> int:
    e, n = pub
    return pow(msg_int, e, n)


def rsa_decrypt(cipher_int: int, priv: tuple) -> int:
    d, n = priv
    return pow(cipher_int, d, n)


def caesar(text: str, shift: int) -> str:
    out = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            out.append(c)
    return ''.join(out)


def send_json(sock, data: dict) -> None:
    line = json.dumps(data) + "\n"
    sock.sendall(line.encode('utf-8'))


def recv_json(sock_file) -> dict:
    line = sock_file.readline()
    return json.loads(line.decode('utf-8'))


def main():
    pub_bob, priv_bob = gerar_chaves_rsa(4096)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", 1300))
    srv.listen(1)
    print("\n[BOB] Aguardando Alice na porta 1300...\n")

    conn, addr = srv.accept()
    f = conn.makefile('rb')
    print(f"[BOB] Alice conectada: {addr}\n")

    send_json(conn, {"e": pub_bob[0], "n": pub_bob[1]})
    print("[BOB] Chave publica RSA enviada para Alice.")

    alice_pub_raw = recv_json(f)
    pub_alice = (alice_pub_raw["e"], alice_pub_raw["n"])
    print("[BOB] Chave publica RSA de Alice recebida.")

    r1_data = recv_json(f)
    R1 = rsa_decrypt(r1_data["R1_enc"], priv_bob)
    print(f"[BOB] R1 descriptografado: {str(R1)[:40]}...")

    R2 = random.getrandbits(256)
    R2_enc = rsa_encrypt(R2, pub_alice)
    send_json(conn, {"R2_enc": R2_enc})
    print(f"[BOB] R2 gerado e enviado cifrado: {str(R2)[:40]}...")

    shift = (R1 ^ R2) % 26
    print(f"[BOB] Shift Cesar: {shift}\n")

    msg_data = recv_json(f)
    cifrada = msg_data["msg"]
    print(f"[BOB] Mensagem cifrada recebida: {cifrada}")

    decifrada = caesar(cifrada, -shift)
    print(f"[BOB] Mensagem decifrada: {decifrada}")

    resposta = decifrada.upper()
    resposta_cifrada = caesar(resposta, shift)
    send_json(conn, {"msg": resposta_cifrada})
    print(f"[BOB] Resposta enviada (cifrada): {resposta_cifrada}")
    print(f"[BOB] Resposta em claro: {resposta}\n")

    conn.close()
    srv.close()
    print("[BOB] Conexao encerrada.")


if __name__ == "__main__":
    main()