import argparse
import os
import base64
from pathlib import Path
import nacl.secret
import nacl.utils
import nacl.exceptions

def generate_github_secret():
    """Génère une clé PyNaCl de 32 octets et l'encode en texte Base64."""
    raw_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    b64_key = base64.b64encode(raw_key).decode('utf-8')
    
    print("\n" + "="*60)
    print("🔑 NOUVELLE CLÉ GÉNÉRÉE POUR GITHUB SECRETS")
    print("="*60)
    print("Copiez exactement la ligne ci-dessous dans votre secret GitHub :")
    print(f"\n{b64_key}\n")
    print("="*60 + "\n")

def get_secretbox() -> nacl.secret.SecretBox:
    """Récupère la clé depuis l'environnement et la décode de Base64 vers binaire."""
    b64_key = os.environ.get("SECRET_BOX")
    
    if not b64_key:
        raise SystemExit("❌ Variable d'environnement 'SECRET_BOX' introuvable.\n"
                         "Avez-vous bien configuré le secret dans GitHub et rechargé le Codespace ?")
    
    try:
        # On retransforme le texte Base64 en octets bruts pour PyNaCl
        key = base64.b64decode(b64_key.strip())
    except Exception:
        raise SystemExit("❌ Erreur : La clé dans SECRET_BOX n'est pas un Base64 valide.")
    
    if len(key) != nacl.secret.SecretBox.KEY_SIZE:
        raise SystemExit(f"❌ Erreur : La clé décodée fait {len(key)} octets au lieu de {nacl.secret.SecretBox.KEY_SIZE}.")

    return nacl.secret.SecretBox(key)

def encrypt_file(input_path: Path, output_path: Path) -> None:
    box = get_secretbox()
    data = input_path.read_bytes()
    encrypted_data = box.encrypt(data)
    output_path.write_bytes(encrypted_data)

def decrypt_file(input_path: Path, output_path: Path) -> None:
    box = get_secretbox()
    encrypted_data = input_path.read_bytes()
    
    try:
        decrypted_data = box.decrypt(encrypted_data)
    except nacl.exceptions.CryptoError:
        raise SystemExit("❌ Échec : Clé incorrecte ou fichier corrompu (CryptoError).")
    
    output_path.write_bytes(decrypted_data)

def main():
    # Ajout du mode "generate" dans les choix
    p = argparse.ArgumentParser(description="Chiffrement/Déchiffrement PyNaCl via GitHub Secrets.")
    p.add_argument("mode", choices=["encrypt", "decrypt", "generate"], help="Mode d'opération")
    # input et output deviennent optionnels (nargs="?") car ils sont inutiles en mode "generate"
    p.add_argument("input", nargs="?", help="Fichier d'entrée")
    p.add_argument("output", nargs="?", help="Fichier de sortie")
    
    args = p.parse_args()

    # Si l'utilisateur veut juste générer une clé
    if args.mode == "generate":
        generate_github_secret()
        return

    # Vérification des arguments pour encrypt et decrypt
    if not args.input or not args.output:
        raise SystemExit("❌ Erreur : Les fichiers d'entrée et de sortie sont requis pour chiffrer ou déchiffrer.")

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        raise SystemExit(f"❌ Fichier d'entrée introuvable: {in_path}")

    if args.mode == "encrypt":
        encrypt_file(in_path, out_path)
        print(f"✅ Fichier chiffré avec succès : {in_path} -> {out_path}")
    elif args.mode == "decrypt":
        decrypt_file(in_path, out_path)
        print(f"✅ Fichier déchiffré avec succès : {in_path} -> {out_path}")

if __name__ == "__main__":
    main()