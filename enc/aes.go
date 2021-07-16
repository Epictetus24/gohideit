package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"golang.org/x/crypto/argon2"
)

type AESbits struct {
	Encbyte   []byte
	Noncebyte []byte
	Saltbyte  []byte
	Enchex    string
	Keystr    string
	Noncehex  string
	Salthex   string
}

// Encrypt shellcode
func AES256Enc(key string, shellcode []byte) (AESenc AESbits) {
	// https://github.com/gtank/cryptopasta/blob/master/encrypt.go
	// https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/ShellcodeUtils/main.go

	AESenc.Keystr = key

	color.Yellow("[-]AES256 encrypting input file")
	// Generate a salt that is used to generate a 32 byte key with Argon2
	salt := make([]byte, 32)
	_, errReadFull := io.ReadFull(rand.Reader, salt)
	if errReadFull != nil {
		color.Red(fmt.Sprintf("[!]%s", errReadFull.Error()))
		os.Exit(1)
	}
	color.Green(fmt.Sprintf("[+]Argon2 salt (hex): %x", salt))

	// Generate Argon2 ID key from input password using a randomly generated salt
	aesKey := argon2.IDKey([]byte(key), salt, 1, 64*1024, 4, 32)
	// I leave it up to the operator to use the password + salt for decryption or just the Argon2 key
	color.Green(fmt.Sprintf("[+]AES256 key (32-bytes) derived from input password %s (hex): %x", key, aesKey))

	// Generate AES Cipher Block
	cipherBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		color.Red(fmt.Sprintf("[!]%s", err.Error()))
	}
	gcm, errGcm := cipher.NewGCM(cipherBlock)
	if err != nil {
		color.Red(fmt.Sprintf("[!]%s", errGcm.Error()))
		os.Exit(1)
	}

	// Generate a nonce (or IV) for use with the AES256 function
	nonce := make([]byte, gcm.NonceSize())
	_, errNonce := io.ReadFull(rand.Reader, nonce)
	if errNonce != nil {
		color.Red(fmt.Sprintf("[!]%s", errNonce.Error()))
		os.Exit(1)
	}

	color.Green(fmt.Sprintf("[+]AES256 nonce (hex): %x", nonce))

	encryptedBytes := gcm.Seal(nil, nonce, shellcode, nil)

	AESenc.Encbyte = encryptedBytes
	AESenc.Noncebyte = nonce
	AESenc.Saltbyte = salt

	AESenc.Enchex = hex.EncodeToString(AESenc.Encbyte)
	AESenc.Noncehex = hex.EncodeToString(AESenc.Noncebyte)
	AESenc.Salthex = hex.EncodeToString(AESenc.Saltbyte)

	return AESenc

}

func AES256Dec(AESencbits AESbits) []byte {

	// https://github.com/gtank/cryptopasta/blob/master/encrypt.go

	salt := AESencbits.Salthex
	key := AESencbits.Keystr
	inputNonce := AESencbits.Noncehex
	shellcode, errShellcode := hex.DecodeString(AESencbits.Enchex)
	if errShellcode != nil {
		color.Red(fmt.Sprintf("[!]%s", errShellcode.Error()))
		os.Exit(1)
	}

	if salt == "" {
		color.Red("[!]A 32-byte salt in hex format must be provided with the -salt argument to decrypt AES256 input file")
		os.Exit(1)
	}
	if len(salt) != 64 {
		color.Red("[!]A 32-byte salt in hex format must be provided with the -salt argument to decrypt AES256 input file")
		color.Red(fmt.Sprintf("[!]A %d byte salt was provided", len(salt)/2))
		os.Exit(1)
	}

	saltDecoded, errSaltDecoded := hex.DecodeString(salt)
	if errSaltDecoded != nil {
		color.Red(fmt.Sprintf("[!]%s", errSaltDecoded.Error()))
		os.Exit(1)
	}

	aesKey := argon2.IDKey([]byte(key), saltDecoded, 1, 64*1024, 4, 32)
	color.Yellow("[-]AES256 key (hex): %x", aesKey)

	cipherBlock, err := aes.NewCipher(aesKey)
	if err != nil {
		color.Red(fmt.Sprintf("[!]%s", err.Error()))
	}

	gcm, errGcm := cipher.NewGCM(cipherBlock)
	if err != nil {
		color.Red(fmt.Sprintf("[!]%s", errGcm.Error()))
		os.Exit(1)
	}

	if len(shellcode) < gcm.NonceSize() {
		color.Red("[!]Malformed ciphertext is larger than nonce")
		os.Exit(1)
	}

	if len(inputNonce) != gcm.NonceSize()*2 {
		color.Red("[!]A nonce, in hex, must be provided with the -nonce argument to decrypt the AES256 input file")
		color.Red(fmt.Sprintf("[!]A %d byte nonce was provided but %d byte nonce was expected", len(inputNonce)/2, gcm.NonceSize()))
		os.Exit(1)
	}
	decryptNonce, errDecryptNonce := hex.DecodeString(inputNonce)
	if errDecryptNonce != nil {
		color.Red("[!]%s", errDecryptNonce.Error())
		os.Exit(1)
	}
	color.Yellow(fmt.Sprintf("[-]AES256 nonce (hex): %x", decryptNonce))

	var errDecryptedBytes error
	decryptedBytes, errDecryptedBytes := gcm.Open(nil, decryptNonce, shellcode, nil)
	if errDecryptedBytes != nil {
		color.Red("[!] Well shit, decryption failed for some reason.\n")
		color.Red("[!]%s", errDecryptedBytes.Error())

		os.Exit(1)
	}
	color.Green("Decrypt Successful!")

	return decryptedBytes

}
