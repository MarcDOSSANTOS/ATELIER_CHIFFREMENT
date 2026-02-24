import argparse
import os
from pathlib import Path
from cryptography.fernet import Fernet

def get_fernet() -> Fernet:
    # On récupère directement le secret depuis les variables d'environnement de Codespaces
    key = os.environ.get("FERNET_KEY")
    
    if not key:
        raise SystemExit("❌ Variable d'environnement 'FERNET_KEY' introuvable.\n"
                         "Assurez-vous que le secret est bien configuré dans GitHub et que vous avez rechargé votre Codespace.")
    
    # On supprime les éventuels espaces/retours à la ligne cachés et on encode
    return Fernet(key.strip().encode())

def encrypt_file(input_path: Path, output_path: Path) -> None:
    f = get_fernet()
    data = input_path.read_bytes()
    token = f.encrypt(data)
    output_path.write_bytes(token)

def decrypt_file(input_path: Path, output_path: Path) -> None:
    f = get_fernet()
    token = input_path.read_bytes()
    data = f.decrypt(token)  # lève InvalidToken si la clé est mauvaise ou si le fichier est altéré
    output_path.write_bytes(data)

def main():
    p = argparse.ArgumentParser(description="Chiffrement/Déchiffrement sécurisé avec Fernet (via GitHub Secrets).")
    p.add_argument("mode", choices=["encrypt", "decrypt"])
    p.add_argument("input", help="Fichier d'entrée")
    p.add_argument("output", help="Fichier de sortie")
    
    args = p.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        raise SystemExit(f"❌ Fichier d'entrée introuvable: {in_path}")

    if args.mode == "encrypt":
        encrypt_file(in_path, out_path)
        print(f"✅ Fichier chiffré avec succès : {in_path} -> {out_path}")
    else:
        decrypt_file(in_path, out_path)
        print(f"✅ Fichier déchiffré avec succès : {in_path} -> {out_path}")

if __name__ == "__main__":
    main()