package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func main() {
	// secret key (harus panjang 16, 24, atau 32 byte untuk AES)
	// y0uc@nts3eMe!... mempunyai 16 karakter
	key := []byte("masukkan secret key kamu disini")

	// menggunakan tools dcode.fr, chipertext terdeteksi sebagai base64
	// maka kita harus decode terlebih dahulu menggunakan std lib dari golang
	ciphertext := "masukkan chipertext kamu disini"

	ct, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		fmt.Println("Error decoding ciphertext:", err)
		return
	}

	// initialization vector (IV) untuk CBC (biasanya 16 byte untuk AES)
	// dalam kasus sebenarnya, IV mungkin ditemukan di file yang dienkripsi
	iv := make([]byte, aes.BlockSize)

	// proses decrypt
	// untuk proses decrypt menggunakan AES-CBC bisa lihat di example penggunaan stdlib ini di
	// https://pkg.go.dev/crypto/cipher#example-NewCBCDecrypter
	plaintext, err := decryptCBC(ct, key, iv)
	if err != nil {
		fmt.Println("Error decrypting ciphertext:", err)
		return
	}

	// gabungkan hasil dekripsi
	// menggunakan tools dcode.fr, 7488e331b8b64e5794da3fa4eb10ad5d (MD5) == admin12345
	finalPlaintext := string(plaintext) + "admin12345"
	fmt.Println("Final Plaintext:", finalPlaintext)
}

// fungsi untuk mendekripsi menggunakan AES-CBC
func decryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %w", err)
	}

	// chipertext harus habis dibagi dengan aes block size (16, 24, atau 32 byte)
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// hapus padding jika ada
	plaintext = removePKCS7Padding(plaintext)
	return plaintext, nil
}

// fungsi untuk menghapus padding PKCS7
func removePKCS7Padding(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}
