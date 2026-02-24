import argparse
from pathlib import Path
import nacl.secret
import nacl.utils
import nacl.exceptions

# J'ai ajouté un paramètre "auto_generate" qui dit au script s'il a le droit de créer la clé
def get_secretbox(key_path: Path, auto_generate: bool = False) -> nacl.secret.SecretBox:
    if not key_path.exists():
        if auto_generate:
            print(f"🔑 Aucune clé trouvée. Génération automatique d'une nouvelle clé dans : {key_path}")
            # Génère 32 octets aléatoires et les écrit directement dans le fichier
            key_path.write_bytes(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE))
        else:
            raise SystemExit(f"❌ Fichier de clé introuvable : {key_path}\n"
                             "Impossible de déchiffrer sans la clé d'origine.")
    
    key = key_path.read_bytes()
    
    if len(key) != nacl.secret.SecretBox.KEY_SIZE:
        raise SystemExit(f"❌ Erreur : La clé doit faire exactement {nacl.secret.SecretBox.KEY_SIZE} octets. "
                         f"Votre fichier en contient {len(key)}.")

    return nacl.secret.SecretBox(key)

def encrypt_file(key_path: Path, input_path: Path, output_path: Path) -> None:
    # Autorise la création de la clé si elle n'existe pas
    box = get_secretbox(key_path, auto_generate=True)
    data = input_path.read_bytes()
    
    encrypted_data = box.encrypt(data)
    output_path.write_bytes(encrypted_data)

def decrypt_file(key_path: Path, input_path: Path, output_path: Path) -> None:
    # Interdit la création de la clé : on en a besoin d'une existante pour déchiffrer
    box = get_secretbox(key_path, auto_generate=False)
    encrypted_data = input_path.read_bytes()
    
    try:
        decrypted_data = box.decrypt(encrypted_data)
    except nacl.exceptions.CryptoError:
        raise SystemExit("❌ Échec : Clé incorrecte ou fichier corrompu (CryptoError).")
    
    output_path.write_bytes(decrypted_data)

def main():
    p = argparse.ArgumentParser(description="Chiffrement/Déchiffrement avec PyNaCl (SecretBox).")
    p.add_argument("mode", choices=["encrypt", "decrypt"])
    p.add_argument("input", help="Fichier d'entrée")
    p.add_argument("output", help="Fichier de sortie")
    p.add_argument("-k", "--key", default="secret2.key", help="Fichier contenant la clé (par défaut: secret2.key)")
    
    args = p.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)
    key_path = Path(args.key)

    if not in_path.exists():
        raise SystemExit(f"❌ Fichier d'entrée introuvable: {in_path}")

    if args.mode == "encrypt":
        encrypt_file(key_path, in_path, out_path)
        print(f"✅ Fichier chiffré avec succès : {in_path} -> {out_path}")
    else:
        decrypt_file(key_path, in_path, out_path)
        print(f"✅ Fichier déchiffré avec succès : {in_path} -> {out_path}")

if __name__ == "__main__":
    main()