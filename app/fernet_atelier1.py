import argparse
from pathlib import Path
from cryptography.fernet import Fernet

# 1. La fonction prend maintenant le chemin du fichier de clé en paramètre
def get_fernet(key_path: Path) -> Fernet:
    if not key_path.exists():
        raise SystemExit(f"❌ Fichier de clé introuvable : {key_path}\n"
                         "Tu peux générer une clé et la sauvegarder dans un fichier via :\n"
                         "python -c \"from cryptography.fernet import Fernet; open('secret.key', 'wb').write(Fernet.generate_key())\"")
    
    # On lit le contenu du fichier et on supprime les éventuels espaces/retours à la ligne avec .strip()
    key = key_path.read_text().strip()
    return Fernet(key.encode())

def encrypt_file(key_path: Path, input_path: Path, output_path: Path) -> None:
    f = get_fernet(key_path)
    data = input_path.read_bytes()
    token = f.encrypt(data)
    output_path.write_bytes(token)

def decrypt_file(key_path: Path, input_path: Path, output_path: Path) -> None:
    f = get_fernet(key_path)
    token = input_path.read_bytes()
    data = f.decrypt(token)  # lève InvalidToken si la clé est mauvaise ou si le fichier est altéré
    output_path.write_bytes(data)

def main():
    p = argparse.ArgumentParser(description="Chiffrement/Déchiffrement de fichiers avec Fernet (cryptography).")
    p.add_argument("mode", choices=["encrypt", "decrypt"])
    p.add_argument("input", help="Fichier d'entrée")
    p.add_argument("output", help="Fichier de sortie")
    
    # 2. Ajout de l'argument pour spécifier le fichier contenant la clé
    p.add_argument("-k", "--key", default="secret.key", help="Fichier contenant la clé (par défaut: secret.key)")
    
    args = p.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    key_path = Path(args.key)

    if not in_path.exists():
        raise SystemExit(f"❌ Fichier introuvable: {in_path}")

    if args.mode == "encrypt":
        encrypt_file(key_path, in_path, out_path)
        print(f"✅ Chiffré: {in_path} -> {out_path}")
    else:
        decrypt_file(key_path, in_path, out_path)
        print(f"✅ Déchiffré: {in_path} -> {out_path}")

if __name__ == "__main__":
    main()