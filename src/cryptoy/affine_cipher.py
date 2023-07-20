from math import (
    gcd,
)

from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement affine

# assert affine_cipher.compute_permutation(2, 2, 5) == [2, 4, 1, 3, 0]
def compute_permutation(a: int, b: int, n: int) -> list[int]:
    return [(a * i + b) % n for i in range (0, n)]

# assert affine_cipher.compute_inverse_permutation(2, 2, 5) == [4, 2, 0, 3, 1]
def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    perm = compute_permutation(a, b, n)
    inv_perm = [0]*n
    for i in range(0, n):
        inv_perm[perm[i]] = i
    return inv_perm

def encrypt(msg: str, a: int, b: int) -> str:
    unicodes =  str_to_unicodes(msg)
    all_perms = compute_permutation(a, b, 1114112)
    perms = [all_perms[i] for i in unicodes]
    return unicodes_to_str(perms)

def encrypt_optimized(msg: str, a: int, b: int) -> str:
    unicodes =  str_to_unicodes(msg)
    perms = [(a * i + b) % 1114112 for i in unicodes]
    return unicodes_to_str(perms)


def decrypt(msg: str, a: int, b: int) -> str:
    # D(y) = (a^-1)(y - b) mod m
    # A implémenter, en utilisant compute_inverse_permutation, str_to_unicodes et unicodes_to_str
    unicodes =  str_to_unicodes(msg)
    all_inv_perms = compute_inverse_permutation(a, b, 1114112)
    inv_perms = [all_inv_perms[y] for y in unicodes]
    return unicodes_to_str(inv_perms)


def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    # A implémenter, sans utiliser compute_inverse_permutation
    # On suppose que a_inverse a été précalculé en utilisant compute_affine_key_inverse, et passé
    # a la fonction
    unicodes =  str_to_unicodes(msg)
    inv_perms = [(a_inverse*(y - b)) % 1114112 for y in unicodes]
    return unicodes_to_str(inv_perms)


def compute_affine_keys(n: int) -> list[int]:
    # A implémenter, doit calculer l'ensemble des nombre a entre 1 et n tel que gcd(a, n) == 1
    # c'est à dire les nombres premiers avec n
    return [i for i in range(0, n) if gcd(i, n) == 1]


def compute_affine_key_inverse(a: int, affine_keys: list, n: int) -> int:
    # Trouver a_1 dans affine_keys tel que a * a_1 % N == 1 et le renvoyer
    # Placer le code ici (une boucle)

    for x in affine_keys:
        if(a * x % n == 1):
            return x

    # Si a_1 n'existe pas, alors a n'a pas d'inverse, on lance une erreur:
    raise RuntimeError(f"{a} has no inverse")


def attack() -> tuple[str, tuple[int, int]]:
    s = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg et b == 58

    # Placer le code ici
    for a in compute_affine_keys(58):
        dec = decrypt(s, a, 58)
        if ("bombe" in dec):
            return (dec, (a, 58))

    raise RuntimeError("Failed to attack")


def attack_optimized() -> tuple[str, tuple[int, int]]:
    s = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg

    key_list = compute_affine_keys(1114112)

    # Placer le code ici
    for i, a in enumerate(key_list):
        print("a:", i, "/", len(key_list))
        try:
            a_1 = compute_affine_key_inverse(a, key_list, 1114112)
        except:
            continue

        for b in range(1, 10001):
            dec = decrypt_optimized(s, a_1, b)
            if ("bombe" in dec):
                return (dec, (a, b))

    raise RuntimeError("Failed to attack")
