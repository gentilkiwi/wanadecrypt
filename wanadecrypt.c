/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com

	With BIG thanks and love to:
	- @msuiche
	- @halsten
	- @malwareunicorn

	.. Just to help ...

	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include <Windows.h>
#include <stdio.h>

#define RSA_2048_ENC	256 // 2048 / 8
#define WANA_MAGIC		((ULONGLONG) 0x21595243414e4157) // WANACRY!

typedef struct _WANA_FORMAT {
	ULONGLONG magic;	// WANA_MAGIC
	ULONG enc_keysize;	// RSA_2048_ENC
	BYTE key[RSA_2048_ENC];
	ULONG unkOperation;	// 4
	ULONGLONG qwDataSize; 
	BYTE data[ANYSIZE_ARRAY];
} WANA_FORMAT, *PWANA_FORMAT;

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, *PGENERICKEY_BLOB;

BOOL SIMPLE_kull_m_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey);
BOOL SIMPLE_kull_m_file_readData(PCWCHAR fileName, PBYTE * data, PDWORD lenght);
BOOL SIMPLE_kull_m_file_writeData(PCWCHAR fileName, LPCVOID data, DWORD lenght);

int wmain(int argc, wchar_t * argv[])
{
	HCRYPTPROV hProv;
	HCRYPTKEY hRsaKey, hAesKey;
	PBYTE pbRsaKey;
	PWANA_FORMAT pbEncData;
	DWORD cbRsaKey, cbEncData, cbRealDataLen, cryptoMode = CRYPT_MODE_CBC;
	PWCHAR p;

	if(argc > 2)
	{
		wprintf(L"Using \'%s\' to decrypt \'%s\' file...\n\n", argv[1], argv[2]);
		if(SIMPLE_kull_m_file_readData(argv[1], &pbRsaKey, &cbRsaKey))
		{
			if(SIMPLE_kull_m_file_readData(argv[2], (PBYTE *) &pbEncData, &cbEncData))
			{
				if(p = wcsrchr(argv[2], L'.'))
				{
					*p = L'\0'; // 'delete' the WNCRY extension
					if(pbEncData->magic == WANA_MAGIC)
					{
						wprintf(L"Mode(?)   : %u\nFilesize  : %llu\n", pbEncData->unkOperation, pbEncData->qwDataSize);
						if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) // we'll do RSA / AES stuff
						{
							if(CryptImportKey(hProv, pbRsaKey, cbRsaKey, 0, 0, &hRsaKey)) // let's import the user PrivateKey - I hope you have it :(
							{
								if(CryptDecrypt(hRsaKey, 0, TRUE, 0, pbEncData->key, &pbEncData->enc_keysize)) // decrypt the raw AES key from your RSA key
								{
									if(SIMPLE_kull_m_crypto_hkey(hProv, CALG_AES_128, pbEncData->key, pbEncData->enc_keysize, 0, &hAesKey)) // let's make a AES 128 Windows key from raw bytes
									{
										if(CryptSetKeyParam(hAesKey, KP_MODE, (PBYTE) &cryptoMode, 0)) // we'll do CBC
										{
											cbRealDataLen = cbEncData - FIELD_OFFSET(WANA_FORMAT, data);
											if(CryptDecrypt(hAesKey, 0, FALSE, 0, pbEncData->data, &cbRealDataLen)) // decrypt final data (padding issue, so 'FALSE' arg)
											{
												if(SIMPLE_kull_m_file_writeData(argv[2], pbEncData->data, (ULONG) pbEncData->qwDataSize))
													wprintf(L"Final file: %s\n", argv[2]);
												else wprintf(L"ERROR: writing final file \'%s\': %u\n", argv[2], GetLastError());
											}
											else wprintf(L"ERROR: CryptDecrypt: %u\n", GetLastError());
										}
										CryptDestroyKey(hAesKey);
									}
								}
								else wprintf(L"ERROR: CryptDecrypt: %u\n", GetLastError());
								CryptDestroyKey(hRsaKey);
							}
							else wprintf(L"ERROR: CryptImportKey: %u\n", GetLastError());
							CryptReleaseContext(hProv, 0);
						}
						else wprintf(L"ERROR: CryptAcquireContext: %u\n", GetLastError());
					}
					else wprintf(L"ERROR: WANACRY! magic number not found\n");
				}
				else wprintf(L"ERROR: no \'.\' at the end of the user file ?\n");
				LocalFree(pbRsaKey);
			}
			else wprintf(L"ERROR: reading userfile \'%s\': %u\n", argv[2], GetLastError());
			LocalFree(pbEncData);
		}
		else wprintf(L"ERROR: reading privatekey file \'%s\': %u\n", argv[1], GetLastError());
	}
	else wprintf(L"ERROR: program needs two arguments: <userprivatekey> <userfile.WNCRY>\n");
	return 0;
}

BOOL SIMPLE_kull_m_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey)
{
	BOOL status = FALSE;
	PGENERICKEY_BLOB keyBlob;
	DWORD szBlob = sizeof(GENERICKEY_BLOB) + keyLen;

	if(keyBlob = (PGENERICKEY_BLOB) LocalAlloc(LPTR, szBlob))
	{
		keyBlob->Header.bType = PLAINTEXTKEYBLOB;
		keyBlob->Header.bVersion = CUR_BLOB_VERSION;
		keyBlob->Header.reserved = 0;
		keyBlob->Header.aiKeyAlg = calgid;
		keyBlob->dwKeyLen = keyLen;
		RtlCopyMemory((PBYTE) keyBlob + sizeof(GENERICKEY_BLOB), key, keyBlob->dwKeyLen);
		status = CryptImportKey(hProv, (LPCBYTE) keyBlob, szBlob, 0, flags, hKey);
		LocalFree(keyBlob);
	}
	return status;
}

BOOL SIMPLE_kull_m_file_readData(PCWCHAR fileName, PBYTE * data, PDWORD lenght)
{
	BOOL reussite = FALSE;
	DWORD dwBytesReaded;
	LARGE_INTEGER filesize;
	HANDLE hFile = NULL;

	if((hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) && hFile != INVALID_HANDLE_VALUE)
	{
		if(GetFileSizeEx(hFile, &filesize) && !filesize.HighPart)
		{
			*lenght = filesize.LowPart;
			if(*data = (PBYTE) LocalAlloc(LPTR, *lenght))
			{
				if(!(reussite = ReadFile(hFile, *data, *lenght, &dwBytesReaded, NULL) && (*lenght == dwBytesReaded)))
					LocalFree(*data);
			}
		}
		CloseHandle(hFile);
	}
	return reussite;
}

BOOL SIMPLE_kull_m_file_writeData(PCWCHAR fileName, LPCVOID data, DWORD lenght)
{
	BOOL reussite = FALSE;
	DWORD dwBytesWritten = 0;
	HANDLE hFile = NULL;

	if((hFile = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)) && hFile != INVALID_HANDLE_VALUE)
	{
		if(WriteFile(hFile, data, lenght, &dwBytesWritten, NULL) && (lenght == dwBytesWritten))
			reussite = FlushFileBuffers(hFile);
		CloseHandle(hFile);
	}
	return reussite;
}