#!/usr/bin/env bash
# =============================================================================
#  crypto_tool.sh  —  OpenSSL Encryption / Decryption Automation
#  Supports: Symmetric (AES-256-CBC) and Asymmetric (RSA) for files, folders, text
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     RESET='\033[0m'

ok()   { echo -e "${GREEN}[✔]${RESET} $*"; }
err()  { echo -e "${RED}[✘] ERROR:${RESET} $*" >&2; }
info() { echo -e "${CYAN}[i]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
header() {
  echo ""
  echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════╗${RESET}"
  printf  "${BOLD}${CYAN}║${RESET}  %-40s${BOLD}${CYAN}║${RESET}\n" "$1"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════╝${RESET}"
}

# ── Dependency Check ─────────────────────────────────────────────────────────
check_deps() {
  for dep in openssl tar; do
    if ! command -v "$dep" &>/dev/null; then
      err "'$dep' is not installed. Please install it first."
      exit 1
    fi
  done
}

# ── Pause helper ─────────────────────────────────────────────────────────────
pause() { echo ""; read -rp "  Press [Enter] to continue..."; }

# =============================================================================
#  RSA KEY MANAGEMENT
# =============================================================================

generate_rsa_keys() {
  header "Generate RSA Key Pair"
  read -rp "  Enter key size [2048/4096] (default: 2048): " keysize
  keysize=${keysize:-2048}

  read -rp "  Save private key to [default: private_key.pem]: " privfile
  privfile=${privfile:-private_key.pem}

  read -rp "  Save public key to  [default: public_key.pem]: " pubfile
  pubfile=${pubfile:-public_key.pem}

  echo ""
  info "Generating $keysize-bit RSA key pair..."

  # Generate private key
  openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:"$keysize" \
    -out "$privfile" 2>/dev/null

  # Extract public key
  openssl rsa -pubout \
    -in  "$privfile" \
    -out "$pubfile"  2>/dev/null

  ok "Private key saved → $privfile"
  ok "Public  key saved → $pubfile"
  warn "Keep '$privfile' secret! Never share it."
  pause
}

# =============================================================================
#  SYMMETRIC ENCRYPTION  (AES-256-CBC)
# =============================================================================

sym_encrypt_text() {
  header "Symmetric — Encrypt Text"
  read -rp "  Enter text to encrypt: " plaintext
  read -rp "  Output file [default: encrypted_text.enc]: " outfile
  outfile=${outfile:-encrypted_text.enc}
  read -rsp "  Enter passphrase: " pass; echo
  read -rsp "  Confirm passphrase: " pass2; echo

  if [[ "$pass" != "$pass2" ]]; then
    err "Passphrases do not match."; pause; return
  fi

  echo "$plaintext" | openssl enc -aes-256-cbc \
    -pbkdf2 -iter 100000 \
    -pass pass:"$pass" \
    -out "$outfile" 2>/dev/null

  ok "Text encrypted → $outfile"
  pause
}

sym_decrypt_text() {
  header "Symmetric — Decrypt Text"
  read -rp "  Encrypted file path: " infile
  [[ ! -f "$infile" ]] && { err "File not found: $infile"; pause; return; }
  read -rsp "  Enter passphrase: " pass; echo

  result=$(openssl enc -d -aes-256-cbc \
    -pbkdf2 -iter 100000 \
    -pass pass:"$pass" \
    -in "$infile" 2>/dev/null) || {
    err "Decryption failed. Wrong passphrase or corrupted file."
    pause; return
  }

  echo ""
  ok "Decrypted text:"
  echo -e "${BOLD}${GREEN}─────────────────────────────${RESET}"
  echo "$result"
  echo -e "${BOLD}${GREEN}─────────────────────────────${RESET}"
  pause
}

sym_encrypt_file() {
  header "Symmetric — Encrypt File"
  read -rp "  Input file path: " infile
  [[ ! -f "$infile" ]] && { err "File not found: $infile"; pause; return; }

  outfile="${infile}.enc"
  read -rp "  Output file [default: $outfile]: " custom
  outfile=${custom:-$outfile}

  read -rsp "  Enter passphrase: " pass; echo
  read -rsp "  Confirm passphrase: " pass2; echo
  [[ "$pass" != "$pass2" ]] && { err "Passphrases do not match."; pause; return; }

  openssl enc -aes-256-cbc \
    -pbkdf2 -iter 100000 \
    -pass pass:"$pass" \
    -in  "$infile" \
    -out "$outfile" 2>/dev/null

  ok "File encrypted → $outfile"
  pause
}

sym_decrypt_file() {
  header "Symmetric — Decrypt File"
  read -rp "  Encrypted file path: " infile
  [[ ! -f "$infile" ]] && { err "File not found: $infile"; pause; return; }

  # Guess output name by stripping .enc
  outfile="${infile%.enc}"
  [[ "$outfile" == "$infile" ]] && outfile="${infile}.dec"
  read -rp "  Output file [default: $outfile]: " custom
  outfile=${custom:-$outfile}

  read -rsp "  Enter passphrase: " pass; echo

  openssl enc -d -aes-256-cbc \
    -pbkdf2 -iter 100000 \
    -pass pass:"$pass" \
    -in  "$infile" \
    -out "$outfile" 2>/dev/null || {
    err "Decryption failed. Wrong passphrase or corrupted file."
    pause; return
  }

  ok "File decrypted → $outfile"
  pause
}

sym_encrypt_folder() {
  header "Symmetric — Encrypt Folder"
  read -rp "  Folder path to encrypt: " folder
  [[ ! -d "$folder" ]] && { err "Folder not found: $folder"; pause; return; }

  archive="${folder%/}.tar.gz"
  outfile="${folder%/}.tar.gz.enc"
  read -rp "  Output file [default: $outfile]: " custom
  outfile=${custom:-$outfile}

  read -rsp "  Enter passphrase: " pass; echo
  read -rsp "  Confirm passphrase: " pass2; echo
  [[ "$pass" != "$pass2" ]] && { err "Passphrases do not match."; pause; return; }

  info "Compressing folder → $archive ..."
  tar -czf "$archive" "$folder"

  info "Encrypting archive..."
  openssl enc -aes-256-cbc \
    -pbkdf2 -iter 100000 \
    -pass pass:"$pass" \
    -in  "$archive" \
    -out "$outfile" 2>/dev/null

  rm -f "$archive"
  ok "Folder encrypted → $outfile"
  info "Original folder is NOT deleted. Remove it manually if needed."
  pause
}

sym_decrypt_folder() {
  header "Symmetric — Decrypt Folder"
  read -rp "  Encrypted folder file path (.enc): " infile
  [[ ! -f "$infile" ]] && { err "File not found: $infile"; pause; return; }

  tmparchive="${infile%.enc}"
  [[ "$tmparchive" == "$infile" ]] && tmparchive="${infile}.tar.gz"
  read -rp "  Extract to directory [default: ./decrypted_folder]: " outdir
  outdir=${outdir:-./decrypted_folder}
  mkdir -p "$outdir"

  read -rsp "  Enter passphrase: " pass; echo

  info "Decrypting..."
  openssl enc -d -aes-256-cbc \
    -pbkdf2 -iter 100000 \
    -pass pass:"$pass" \
    -in  "$infile" \
    -out "$tmparchive" 2>/dev/null || {
    err "Decryption failed. Wrong passphrase or corrupted file."
    rm -f "$tmparchive"; pause; return
  }

  info "Extracting to $outdir ..."
  tar -xzf "$tmparchive" -C "$outdir"
  rm -f "$tmparchive"

  ok "Folder decrypted and extracted → $outdir"
  pause
}

# =============================================================================
#  ASYMMETRIC ENCRYPTION  (RSA — Hybrid for large data)
# =============================================================================
# NOTE: RSA alone can only encrypt data smaller than the key size (~245 bytes
# for 2048-bit RSA). For files and folders we use HYBRID ENCRYPTION:
#   Encrypt:  generate random AES key → encrypt data with AES → encrypt AES key with RSA
#   Decrypt:  decrypt AES key with RSA private key → decrypt data with AES key

asym_encrypt_text() {
  header "Asymmetric — Encrypt Text (RSA)"
  read -rp "  Enter text to encrypt: " plaintext
  read -rp "  Public key file [default: public_key.pem]: " pubkey
  pubkey=${pubkey:-public_key.pem}
  [[ ! -f "$pubkey" ]] && { err "Public key not found: $pubkey"; pause; return; }

  read -rp "  Output file [default: encrypted_text.rsa.enc]: " outfile
  outfile=${outfile:-encrypted_text.rsa.enc}

  # Check if text fits direct RSA encryption (< 200 bytes to be safe)
  textlen=${#plaintext}
  if (( textlen < 200 )); then
    echo "$plaintext" | openssl pkeyutl -encrypt \
      -pubin -inkey "$pubkey" \
      -out "$outfile" 2>/dev/null
    ok "Text encrypted directly with RSA → $outfile"
  else
    # Hybrid: too large for direct RSA
    info "Text > 200 chars. Using hybrid RSA+AES encryption..."
    tmpfile=$(mktemp)
    echo "$plaintext" > "$tmpfile"
    _hybrid_encrypt "$tmpfile" "$pubkey" "$outfile"
    rm -f "$tmpfile"
    ok "Text encrypted (hybrid RSA+AES) → $outfile"
  fi
  pause
}

asym_decrypt_text() {
  header "Asymmetric — Decrypt Text (RSA)"
  read -rp "  Encrypted file path: " infile
  [[ ! -f "$infile" ]] && { err "File not found: $infile"; pause; return; }
  read -rp "  Private key file [default: private_key.pem]: " privkey
  privkey=${privkey:-private_key.pem}
  [[ ! -f "$privkey" ]] && { err "Private key not found: $privkey"; pause; return; }

  # Try direct RSA first, fallback to hybrid
  result=$(openssl pkeyutl -decrypt \
    -inkey "$privkey" \
    -in "$infile" 2>/dev/null) && {
    echo ""
    ok "Decrypted text:"
    echo -e "${BOLD}${GREEN}─────────────────────────────${RESET}"
    echo "$result"
    echo -e "${BOLD}${GREEN}─────────────────────────────${RESET}"
  } || {
    info "Trying hybrid RSA+AES decryption..."
    tmpout=$(mktemp)
    _hybrid_decrypt "$infile" "$privkey" "$tmpout" && {
      echo ""
      ok "Decrypted text:"
      echo -e "${BOLD}${GREEN}─────────────────────────────${RESET}"
      cat "$tmpout"
      echo -e "${BOLD}${GREEN}─────────────────────────────${RESET}"
    } || err "Decryption failed. Wrong key or corrupted file."
    rm -f "$tmpout"
  }
  pause
}

# ── Hybrid Encrypt helper ─────────────────────────────────────────────────────
_hybrid_encrypt() {
  local infile="$1" pubkey="$2" outfile="$3"
  local tmpdir; tmpdir=$(mktemp -d)
  local aeskey="${tmpdir}/aes.key"
  local encdata="${tmpdir}/data.enc"
  local enckey="${tmpdir}/key.enc"

  # 1. Generate random 256-bit AES key
  openssl rand -out "$aeskey" 32

  # 2. Encrypt data with AES key
  openssl enc -aes-256-cbc \
    -pbkdf2 -iter 100000 \
    -pass file:"$aeskey" \
    -in  "$infile" \
    -out "$encdata" 2>/dev/null

  # 3. Encrypt AES key with RSA public key
  openssl pkeyutl -encrypt \
    -pubin -inkey "$pubkey" \
    -in  "$aeskey" \
    -out "$enckey" 2>/dev/null

  # 4. Bundle: [4 bytes key length][encrypted key][encrypted data]
  local keylen; keylen=$(wc -c < "$enckey")
  printf '%08x' "$keylen" | xxd -r -p > "$outfile"
  cat "$enckey" "$encdata"  >> "$outfile"

  rm -rf "$tmpdir"
}

# ── Hybrid Decrypt helper ─────────────────────────────────────────────────────
_hybrid_decrypt() {
  local infile="$1" privkey="$2" outfile="$3"
  local tmpdir; tmpdir=$(mktemp -d)
  local aeskey="${tmpdir}/aes.key"
  local encdata="${tmpdir}/data.enc"
  local enckey="${tmpdir}/key.enc"

  # 1. Read key length from first 4 bytes
  local keylen; keylen=$(dd if="$infile" bs=1 count=4 2>/dev/null | xxd -p | printf '%d' "0x$(cat)")
  if (( keylen <= 0 || keylen > 1024 )); then
    rm -rf "$tmpdir"; return 1
  fi

  # 2. Extract encrypted AES key and encrypted data
  dd if="$infile" bs=1 skip=4 count="$keylen" of="$enckey" 2>/dev/null
  dd if="$infile" bs=1 skip=$((4 + keylen))   of="$encdata" 2>/dev/null

  # 3. Decrypt AES key with RSA private key
  openssl pkeyutl -decrypt \
    -inkey "$privkey" \
    -in  "$enckey" \
    -out "$aeskey" 2>/dev/null || { rm -rf "$tmpdir"; return 1; }

  # 4. Decrypt data with AES key
  openssl enc -d -aes-256-cbc \
    -pbkdf2 -iter 100000 \
    -pass file:"$aeskey" \
    -in  "$encdata" \
    -out "$outfile" 2>/dev/null || { rm -rf "$tmpdir"; return 1; }

  rm -rf "$tmpdir"
  return 0
}

asym_encrypt_file() {
  header "Asymmetric — Encrypt File (Hybrid RSA+AES)"
  read -rp "  Input file path: " infile
  [[ ! -f "$infile" ]] && { err "File not found: $infile"; pause; return; }
  read -rp "  Public key file [default: public_key.pem]: " pubkey
  pubkey=${pubkey:-public_key.pem}
  [[ ! -f "$pubkey" ]] && { err "Public key not found: $pubkey"; pause; return; }

  outfile="${infile}.rsa.enc"
  read -rp "  Output file [default: $outfile]: " custom
  outfile=${custom:-$outfile}

  info "Encrypting (hybrid RSA+AES)..."
  _hybrid_encrypt "$infile" "$pubkey" "$outfile"
  ok "File encrypted → $outfile"
  pause
}

asym_decrypt_file() {
  header "Asymmetric — Decrypt File (Hybrid RSA+AES)"
  read -rp "  Encrypted file path: " infile
  [[ ! -f "$infile" ]] && { err "File not found: $infile"; pause; return; }
  read -rp "  Private key file [default: private_key.pem]: " privkey
  privkey=${privkey:-private_key.pem}
  [[ ! -f "$privkey" ]] && { err "Private key not found: $privkey"; pause; return; }

  outfile="${infile%.rsa.enc}"
  [[ "$outfile" == "$infile" ]] && outfile="${infile}.dec"
  read -rp "  Output file [default: $outfile]: " custom
  outfile=${custom:-$outfile}

  info "Decrypting..."
  _hybrid_decrypt "$infile" "$privkey" "$outfile" || {
    err "Decryption failed. Wrong key or corrupted file."
    rm -f "$outfile"; pause; return
  }
  ok "File decrypted → $outfile"
  pause
}

asym_encrypt_folder() {
  header "Asymmetric — Encrypt Folder (Hybrid RSA+AES)"
  read -rp "  Folder path to encrypt: " folder
  [[ ! -d "$folder" ]] && { err "Folder not found: $folder"; pause; return; }
  read -rp "  Public key file [default: public_key.pem]: " pubkey
  pubkey=${pubkey:-public_key.pem}
  [[ ! -f "$pubkey" ]] && { err "Public key not found: $pubkey"; pause; return; }

  archive="${folder%/}.tar.gz"
  outfile="${folder%/}.tar.gz.rsa.enc"
  read -rp "  Output file [default: $outfile]: " custom
  outfile=${custom:-$outfile}

  info "Compressing folder..."
  tar -czf "$archive" "$folder"

  info "Encrypting (hybrid RSA+AES)..."
  _hybrid_encrypt "$archive" "$pubkey" "$outfile"
  rm -f "$archive"
  ok "Folder encrypted → $outfile"
  info "Original folder is NOT deleted."
  pause
}

asym_decrypt_folder() {
  header "Asymmetric — Decrypt Folder (Hybrid RSA+AES)"
  read -rp "  Encrypted folder file path: " infile
  [[ ! -f "$infile" ]] && { err "File not found: $infile"; pause; return; }
  read -rp "  Private key file [default: private_key.pem]: " privkey
  privkey=${privkey:-private_key.pem}
  [[ ! -f "$privkey" ]] && { err "Private key not found: $privkey"; pause; return; }
  read -rp "  Extract to directory [default: ./decrypted_folder]: " outdir
  outdir=${outdir:-./decrypted_folder}
  mkdir -p "$outdir"

  tmparchive=$(mktemp --suffix=.tar.gz)

  info "Decrypting..."
  _hybrid_decrypt "$infile" "$privkey" "$tmparchive" || {
    err "Decryption failed. Wrong key or corrupted file."
    rm -f "$tmparchive"; pause; return
  }

  info "Extracting to $outdir ..."
  tar -xzf "$tmparchive" -C "$outdir"
  rm -f "$tmparchive"

  ok "Folder decrypted and extracted → $outdir"
  pause
}

# =============================================================================
#  HASH UTILITY  (bonus: verify file integrity)
# =============================================================================

hash_file() {
  header "File Hash (Integrity Check)"
  read -rp "  File path: " infile
  [[ ! -f "$infile" ]] && { err "File not found: $infile"; pause; return; }

  echo ""
  info "Hashes for: $infile"
  echo -e "${BOLD}  MD5    :${RESET} $(openssl dgst -md5    "$infile" | awk '{print $2}')"
  echo -e "${BOLD}  SHA1   :${RESET} $(openssl dgst -sha1   "$infile" | awk '{print $2}')"
  echo -e "${BOLD}  SHA256 :${RESET} $(openssl dgst -sha256 "$infile" | awk '{print $2}')"
  echo -e "${BOLD}  SHA512 :${RESET} $(openssl dgst -sha512 "$infile" | awk '{print $2}')"
  pause
}

# =============================================================================
#  MENUS
# =============================================================================

menu_symmetric() {
  while true; do
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║      SYMMETRIC  (AES-256-CBC)         ║"
    echo "  ╚═══════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "   ${BOLD}1.${RESET} Encrypt text"
    echo -e "   ${BOLD}2.${RESET} Decrypt text"
    echo -e "   ${BOLD}3.${RESET} Encrypt file"
    echo -e "   ${BOLD}4.${RESET} Decrypt file"
    echo -e "   ${BOLD}5.${RESET} Encrypt folder"
    echo -e "   ${BOLD}6.${RESET} Decrypt folder"
    echo -e "   ${BOLD}0.${RESET} ← Back to main menu"
    echo ""
    read -rp "  Choose: " choice
    case "$choice" in
      1) sym_encrypt_text   ;;
      2) sym_decrypt_text   ;;
      3) sym_encrypt_file   ;;
      4) sym_decrypt_file   ;;
      5) sym_encrypt_folder ;;
      6) sym_decrypt_folder ;;
      0) return ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

menu_asymmetric() {
  while true; do
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║    ASYMMETRIC  (RSA + Hybrid AES)     ║"
    echo "  ╚═══════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "   ${BOLD}1.${RESET} Generate RSA key pair"
    echo -e "   ${BOLD}2.${RESET} Encrypt text"
    echo -e "   ${BOLD}3.${RESET} Decrypt text"
    echo -e "   ${BOLD}4.${RESET} Encrypt file"
    echo -e "   ${BOLD}5.${RESET} Decrypt file"
    echo -e "   ${BOLD}6.${RESET} Encrypt folder"
    echo -e "   ${BOLD}7.${RESET} Decrypt folder"
    echo -e "   ${BOLD}0.${RESET} ← Back to main menu"
    echo ""
    read -rp "  Choose: " choice
    case "$choice" in
      1) generate_rsa_keys   ;;
      2) asym_encrypt_text   ;;
      3) asym_decrypt_text   ;;
      4) asym_encrypt_file   ;;
      5) asym_decrypt_file   ;;
      6) asym_encrypt_folder ;;
      7) asym_decrypt_folder ;;
      0) return ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

main_menu() {
  while true; do
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║       OpenSSL Crypto Automation Tool     ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  Encrypt / Decrypt files, folders, text  ║"
    echo "  ╚══════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "   ${BOLD}1.${RESET} 🔑  Symmetric  Encryption  (AES-256-CBC)"
    echo -e "   ${BOLD}2.${RESET} 🔐  Asymmetric Encryption  (RSA + Hybrid)"
    echo -e "   ${BOLD}3.${RESET} #   Hash / Integrity Check"
    echo -e "   ${BOLD}0.${RESET} ✖   Exit"
    echo ""
    read -rp "  Choose: " choice
    case "$choice" in
      1) menu_symmetric   ;;
      2) menu_asymmetric  ;;
      3) hash_file        ;;
      0) echo -e "\n${GREEN}Goodbye!${RESET}\n"; exit 0 ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

# =============================================================================
#  ENTRY POINT
# =============================================================================
check_deps
main_menu
