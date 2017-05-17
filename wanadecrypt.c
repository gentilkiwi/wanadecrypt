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
#include <Shlwapi.h>
#include <stdio.h>

#define RSA_2048_ENC	256 // 2048 / 8
#define WANA_MAGIC		((ULONGLONG) 0x21595243414e4157) // WANACRY!
#define RSA_ENC_SIZE	(RSA_2048_ENC * 5)
#define RSA_DEC_SIZE	1172
#define RSA_BAD_PAD		1225

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

typedef struct _ENC_PRIV_KEY {
	DWORD totalBytes;
	BYTE data[ANYSIZE_ARRAY][RSA_2048_ENC];
} ENC_PRIV_KEY, *PENC_PRIV_KEY;

typedef struct _DEC_PRIV_KEY {
	DWORD totalBytes;
	BYTE data[ANYSIZE_ARRAY];
} DEC_PRIV_KEY, *PDEC_PRIV_KEY;

BOOL SIMPLE_kull_m_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey);
BOOL SIMPLE_kull_m_file_readData(PCWCHAR fileName, PBYTE * data, PDWORD lenght);
BOOL SIMPLE_kull_m_file_writeData(PCWCHAR fileName, LPCVOID data, DWORD lenght);
void decryptFileWithKey(HCRYPTPROV hProv, HCRYPTKEY hUserRsaKey, int argc, wchar_t * argv[]);

int wmain(int argc, wchar_t * argv[])
{
	HCRYPTPROV hProv;
	HCRYPTKEY hMalwareRsaKey, hUserRsaKey;
	PBYTE pbRsaKey;
	DWORD cbRsaKey, cbData, i, dataLen;
	PENC_PRIV_KEY pEnc;
	PDEC_PRIV_KEY pDec;
	PWSTR ext;

	if(argc > 2)
	{
		if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) // we'll do RSA / AES stuff
		{
			ext = PathFindExtension(argv[2]);
			if(ext && (_wcsicmp(ext, L".eky") == 0))
			{
				wprintf(L"Malware PK: %s\nUser EncPK: %s\n", argv[1], argv[2]);
				if(SIMPLE_kull_m_file_readData(argv[1], &pbRsaKey, &cbRsaKey))
				{
					if(CryptImportKey(hProv, pbRsaKey, cbRsaKey, 0, 0, &hMalwareRsaKey)) // let's import the malware PrivateKey - We all hope you have it :(
					{
						if(SIMPLE_kull_m_file_readData(argv[2], (PBYTE *) &pEnc, &cbData))
						{
							if((pEnc->totalBytes == RSA_ENC_SIZE) && (cbData == (pEnc->totalBytes + FIELD_OFFSET(ENC_PRIV_KEY, data))))
							{
								if(pDec = (PDEC_PRIV_KEY) LocalAlloc(LPTR, FIELD_OFFSET(DEC_PRIV_KEY, data) + pEnc->totalBytes)) // 0
								{
									for(i = 0; i < pEnc->totalBytes / RSA_2048_ENC; i++)
									{
										RtlCopyMemory(pDec->data + pDec->totalBytes, pEnc->data[i], RSA_2048_ENC);
										dataLen = RSA_2048_ENC;
										if(CryptDecrypt(hMalwareRsaKey, 0, TRUE, 0, pDec->data + pDec->totalBytes, &dataLen))
											pDec->totalBytes += dataLen;
										else wprintf(L"ERROR: CryptDecrypt(user - %u): %u\n", i, GetLastError());
									}

									switch(pDec->totalBytes)
									{
									case RSA_BAD_PAD:
										wprintf(L"WARNING: user privatekey was encrypted with bad data at the end, fixed from %u to %u\n", RSA_BAD_PAD, RSA_DEC_SIZE);
										pDec->totalBytes = RSA_DEC_SIZE;
										break;
									case RSA_DEC_SIZE:
										wprintf(L"W00T: user privatekey good size ?\n");
										break;
									default:
										wprintf(L"ERROR: Invalid user privatekey size: %u\n", pDec->totalBytes);
									}

									if(pDec->totalBytes == RSA_DEC_SIZE)
									{
										if(CryptImportKey(hProv, pDec->data, pDec->totalBytes, 0, 0, &hUserRsaKey))
										{
											ext[1] = L'p';
											wprintf(L"\nSave DecPK: %s\n", argv[2]);
											if(!SIMPLE_kull_m_file_writeData(argv[2], pDec->data, pDec->totalBytes))
												wprintf(L"ERROR: saving raw user privatekey file \'%s\': %u\n", argv[2], GetLastError());
											decryptFileWithKey(hProv, hUserRsaKey, argc - 3, &argv[3]);
											CryptDestroyKey(hUserRsaKey);
										}
										else wprintf(L"ERROR: CryptImportKey(user): %u\n", GetLastError());
									}
									LocalFree(pDec);
								}
							}
							else wprintf(L"ERROR: abnormal encrypted size (H:%08x, D:%08x, N:%08x)\n",  pEnc->totalBytes, cbData - FIELD_OFFSET(ENC_PRIV_KEY, data), RSA_ENC_SIZE);
							LocalFree(pEnc);
						}
						else wprintf(L"ERROR: reading user encrypted privatekey file \'%s\': %u\n", argv[2], GetLastError());
					}
					else wprintf(L"ERROR: CryptImportKey(malware): %u\n", GetLastError());
					LocalFree(pbRsaKey);
				}
				else wprintf(L"ERROR: reading malware privatekey file \'%s\': %u\n", argv[1], GetLastError());
			}
			else
			{
				wprintf(L"Using raw user private key: \'%s\' to decrypt\n", argv[1]);
				if(SIMPLE_kull_m_file_readData(argv[1], &pbRsaKey, &cbRsaKey))
				{
					if(CryptImportKey(hProv, pbRsaKey, cbRsaKey, 0, 0, &hUserRsaKey)) // let's import the user PrivateKey - I hope you have it :(
					{
						decryptFileWithKey(hProv, hUserRsaKey, argc - 2, &argv[2]);
						CryptDestroyKey(hUserRsaKey);
					}
					else wprintf(L"ERROR: CryptImportKey: %u\n", GetLastError());
					LocalFree(pbRsaKey);
				}
				else wprintf(L"ERROR: reading user privatekey file \'%s\': %u\n", argv[1], GetLastError());
			}
			CryptReleaseContext(hProv, 0);
		}
		else wprintf(L"ERROR: CryptAcquireContext: %u\n", GetLastError());
	}
	else wprintf(L"ERROR: program needs at least two arguments:\n  %s <userprivatekey> <userfile.WNCRY> ...\n  %s <malwareprivatekey> <encrypteduserprivatekey.eky> <userfile.WNCRY> ...\n", argv[0], argv[0]);
	return 0;
}

void decryptFileWithKey(HCRYPTPROV hProv, HCRYPTKEY hUserRsaKey, int argc, wchar_t * argv[])
{
	HCRYPTKEY hUserFileAesKey;
	PWANA_FORMAT pbEncData;
	PWCHAR p;
	DWORD cbEncData, cbRealDataLen, cryptoMode = CRYPT_MODE_CBC;
	int i;

	for(i = 0; i < argc; i++)
	{
		wprintf(L"\nFilename  : %s\n", argv[i]);
		if(SIMPLE_kull_m_file_readData(argv[i], (PBYTE *) &pbEncData, &cbEncData))
		{
			if(p = wcsrchr(argv[i], L'.'))
			{
				*p = L'\0'; // 'delete' the WNCRY extension
				if(pbEncData->magic == WANA_MAGIC)
				{
					wprintf(L"Mode(?)   : %u\nFilesize  : %llu\n", pbEncData->unkOperation, pbEncData->qwDataSize);
					if(CryptDecrypt(hUserRsaKey, 0, TRUE, 0, pbEncData->key, &pbEncData->enc_keysize)) // decrypt the raw AES key from your RSA key
					{
						if(SIMPLE_kull_m_crypto_hkey(hProv, CALG_AES_128, pbEncData->key, pbEncData->enc_keysize, 0, &hUserFileAesKey)) // let's make a AES 128 Windows key from raw bytes
						{
							if(CryptSetKeyParam(hUserFileAesKey, KP_MODE, (PBYTE) &cryptoMode, 0)) // we'll do CBC
							{
								cbRealDataLen = cbEncData - FIELD_OFFSET(WANA_FORMAT, data);
								if(CryptDecrypt(hUserFileAesKey, 0, FALSE, 0, pbEncData->data, &cbRealDataLen)) // decrypt final data (padding issue, so 'FALSE' arg)
								{
									if(SIMPLE_kull_m_file_writeData(argv[i], pbEncData->data, (ULONG) pbEncData->qwDataSize))
										wprintf(L"Final file: %s\n", argv[i]);
									else wprintf(L"ERROR: writing final file \'%s\': %u\n", argv[i], GetLastError());
								}
								else wprintf(L"ERROR: CryptDecrypt: %u\n", GetLastError());
							}
							CryptDestroyKey(hUserFileAesKey);
						}
					}
					else wprintf(L"ERROR: CryptDecrypt: %u\n", GetLastError());
				}
				else wprintf(L"ERROR: WANACRY! magic number not found\n");
			}
			else wprintf(L"ERROR: no \'.\' at the end of the user file ?\n");
			LocalFree(pbEncData);
		}
		else wprintf(L"ERROR: reading input file \'%s\': %u\n", argv[i], GetLastError());
	}
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