#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include "Common.h"


DWORD
MyEncryptBuffer(PBYTE pbInput, DWORD cbInput, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, PKEY_DESC pKeyDesc)
{
    DWORD               dwRet = E_FAIL;
    BCRYPT_ALG_HANDLE   hAlgAes = NULL;                 // Handle to the AES algorithm
    BCRYPT_KEY_HANDLE   hKey = NULL;                    // Handle to the symmetric encryption key
    BYTE                rgbKey[MY_AES_KEYSIZE_BYTES];   // Byte vector storing the encryption key
    BYTE                rgbIV[MY_AES_KEYSIZE_BYTES];    // Byte vector storing the IV

    if (NULL == pbInput || NULL == pbOutput || NULL == pcbResult || NULL == pKeyDesc)
        return ERROR_INVALID_PARAMETER;

    ZeroMemory(pKeyDesc, sizeof(KEY_DESC));

    /*
    * 1. Generate a new random key
    */
    NTSTATUS_API_CHECK_SUCCESS(BCryptGenRandom(
        NULL,
        rgbKey,
        sizeof(rgbKey),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    ));

    /*
    * 2. Generate a new IV
    */
    NTSTATUS_API_CHECK_SUCCESS(BCryptGenRandom(
        NULL,
        rgbIV,
        sizeof(rgbIV),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    ));

    /*
    * 3. Backup IV and key as they will be overwritten by encryption API.
    */
    CopyMemory(pKeyDesc->rgbKey, rgbKey, sizeof(rgbKey));
    CopyMemory(pKeyDesc->rgbIV, rgbIV, sizeof(rgbKey));

    /*
    * 4. Open handle to AES algorithm
    */
    NTSTATUS_API_CHECK_SUCCESS(BCryptOpenAlgorithmProvider(
        &hAlgAes,
        BCRYPT_AES_ALGORITHM,
        MS_PRIMITIVE_PROVIDER,
        0
    ));

    /*
    * 5. Set the chaining mode for AES to CBC
    */
    NTSTATUS_API_CHECK_SUCCESS(BCryptSetProperty(
        hAlgAes,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0
    ));

    /*
    * 6. Import the symmetric key into CryptNG
    */
    NTSTATUS_API_CHECK_SUCCESS(BCryptGenerateSymmetricKey(
        hAlgAes,
        &hKey,
        NULL,
        0,
        rgbKey,
        sizeof(rgbKey),
        0
    ));

    /*
    * 7. Encrypt the content.
    */
    NTSTATUS_API_CHECK_SUCCESS(BCryptEncrypt(
        hKey,
        pbInput,
        cbInput,
        NULL,
        pKeyDesc->rgbIV,
        sizeof(pKeyDesc->rgbIV),
        pbOutput,
        cbOutput,
        pcbResult,
        BCRYPT_BLOCK_PADDING
    ));

    dwRet = ERROR_SUCCESS;

Cleanup:

    if (NULL != hKey)
        BCryptDestroyKey(hKey);

    if (NULL != hAlgAes)
        BCryptCloseAlgorithmProvider(hAlgAes, 0);

    return dwRet;
}

DWORD
MyDecryptBuffer(PBYTE pbInput, DWORD cbInput, PBYTE pbOutput, DWORD cbOutput, DWORD* pcbResult, PKEY_DESC pKeyDesc)
{
    DWORD               dwRet = E_FAIL;
    BCRYPT_ALG_HANDLE   hAlgAes = NULL;
    BCRYPT_KEY_HANDLE   hKey = NULL;

    if (NULL == pbInput || NULL == pbOutput || NULL == pcbResult || NULL == pKeyDesc)
        return ERROR_INVALID_PARAMETER;

    /*
    * 1. Open handle to AES algorithm
    */
    NTSTATUS_API_CHECK_SUCCESS(BCryptOpenAlgorithmProvider(
        &hAlgAes,
        BCRYPT_AES_ALGORITHM,
        MS_PRIMITIVE_PROVIDER,
        0
    ));

    /*
    * 2. Set AES chaining mode to CBC
    */
    NTSTATUS_API_CHECK_SUCCESS(BCryptSetProperty(
        hAlgAes,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0
    ));

    /*
    * 3. Import the encryption key.
    */
    NTSTATUS_API_CHECK_SUCCESS(BCryptGenerateSymmetricKey(
        hAlgAes,
        &hKey,
        NULL,
        0,
        pKeyDesc->rgbKey,
        sizeof(pKeyDesc->rgbKey),
        0
    ));


    /*
    * 4. Decrypt the content.
    */
    NTSTATUS_API_CHECK_SUCCESS(BCryptDecrypt(
        hKey,
        pbInput,
        cbInput,
        NULL,
        pKeyDesc->rgbIV,
        sizeof(pKeyDesc->rgbIV),
        pbOutput,
        cbOutput,
        pcbResult,
        BCRYPT_BLOCK_PADDING
    ));

    dwRet = ERROR_SUCCESS;

Cleanup:

    if (NULL != hKey)
        BCryptDestroyKey(hKey);

    if (NULL != hAlgAes)
        BCryptCloseAlgorithmProvider(hAlgAes, 0);

    return dwRet;
}

DWORD
MyGetCertificateCtxFromHash(LPCWSTR wszStoreName, PCCERT_CONTEXT* ppCertContext, LPCWSTR wszCertHashString)
{
    DWORD           dwRet = 0;
    BYTE            rgbCertHash[20] = { 0 };
    DWORD           cbCertHash = sizeof(rgbCertHash);
    HCERTSTORE      hCertStore = NULL;
    CRYPT_HASH_BLOB hashBlob = { 0 };

    /*
    * 1. Convert the hash tring to binary.
    */
    BOOL_API_CHECK_SUCCESS(CryptStringToBinaryW(
        wszCertHashString,
        wcslen(wszCertHashString),
        CRYPT_STRING_HEXRAW,
        &rgbCertHash[0],
        &cbCertHash,
        NULL,
        NULL
    ));

    /*
    * 2. Open user's store specified in wszStoreName
    */
    HANDLE_API_CHECK_SUCCESS(hCertStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
        wszStoreName
    ));


    hashBlob.cbData = cbCertHash;
    hashBlob.pbData = rgbCertHash;

    /*
    * 3. Try to find the certificate in the store.
    */
    HANDLE_API_CHECK_SUCCESS(*ppCertContext = CertFindCertificateInStore(
        hCertStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SHA1_HASH,
        &hashBlob,
        NULL
    ));

Cleanup:
    if (hCertStore)
        CertCloseStore(hCertStore, 0);

    return dwRet;
}

void
PrintUsage()
{
    printf("%s\n", "filecrypt.exe encrypt file certhash");
    printf("%s\n", "filecrypt.exe decrypt file");
}



int wmain(int argc, wchar_t *argv[])
{
    DWORD           dwRet = 0;                              // Error code for our program
    BOOL            fEncrypt = 0;                           // TRUE if program is doing encryption. FALSE if doing decryption

    // Arguments from command line
    LPWSTR          wszSrcFilepath = NULL;                  // file path of the source file
    LPWSTR          wszDstFilepath = NULL;                  // file path of the destionation file
    LPWSTR          wszCertHash = NULL;                     // thumbprint of the recipient certificate

    // File management
    MAPPING_DESC    srcMappingDesc = { 0 };                 // Reference of the mapping of the source file into program's main memory
    MAPPING_DESC    dstMappingDesc = { 0 };                 // Reference of the mapping of the destination file into program's main memory
    UINT64          ullDstFileSize = 0;                     // size of newly created destination file
    PFILE_HEADER    pFileHeader = NULL;                     // File header of the protected file

    // Crypto specific
    PBYTE           pbEncryptedStart = NULL;                // Position of the payload in the protected file
    UINT64          cbEncryptedStart = 0;                   // size of the payload
    DWORD           cbProcessedBytes = 0;                   // Byte processed by symmetric encryption/decryption
    PCCERT_CONTEXT  pRecipientCertContext = NULL;           // Reference to the recipient's certificate
    KEY_DESC        keyDescriptor = { 0 };                  // Symmetric key information
    DWORD           cbEncryptedRecipientBlobSize = 0;       // Size of the encrypted payload including the padding necessary for AES to operate

    // Sender (encryption) specific:
    BCRYPT_KEY_HANDLE   hRecipientKey = NULL;               // Handle to the recipient's public key
    UINT64              ullEncryptedBufferSize = 0;         // Size of the buffer which will contain the encrypted payload

    // Recipient (decryption) specific:
    NCRYPT_KEY_HANDLE   hNCryptKey = NULL;                  // Handle to the recipiant's private key            
    DWORD           dwKeySpec = 0;                          // KeySpec of the recipient's private key. Should always be NCrypt
    BOOL            fMustFreeRecipientKey = TRUE;           // If we should free the private's key handle after use.



    /*
    * 1. Argument parsing
    */
    if (argc < 3)
    {
        PrintUsage();
        return STATUS_INVALID_PARAMETER;
    }

    if (0 == wcscmp(L"encrypt", argv[1]))
    {
        fEncrypt = TRUE;
        wszCertHash = argv[3];
        wszSrcFilepath = argv[2];
        wszDstFilepath = ComputeDestFilepath(wszSrcFilepath, fEncrypt);
    }
    else if (0 == wcscmp(L"decrypt", argv[1]))
    {
        fEncrypt = FALSE;
        wszSrcFilepath = argv[2];
        wszDstFilepath = ComputeDestFilepath(wszSrcFilepath, fEncrypt);
    }
    else
    {
        PrintUsage();
        return STATUS_INVALID_PARAMETER;
    }

    /*
    * 2. Create the file mapping for the source file.
    * Common to all cases. This is our input file.
    */
    NTSTATUS_API_CHECK_SUCCESS(MyCreateFileMapping(
        wszSrcFilepath, 
        FALSE, 
        0, 
        &srcMappingDesc));

    /*
    * 3. Do Encryption or Decryption
    */
    if (fEncrypt)
    {
        /*
        * We are protecting the file.
        * source file: clear text file.
        * destination file: Protected file aka. encrypted content + header
        */

        /*
        * 3a.1 Adjust size of the payload to account for AES padding.
        * + Compute final size of the output file (header + encrypted payload)
        */
        ullEncryptedBufferSize = srcMappingDesc.ullMappingSize + (srcMappingDesc.ullMappingSize % MY_AES_KEYSIZE_BYTES ? MY_AES_KEYSIZE_BYTES - (srcMappingDesc.ullMappingSize % MY_AES_KEYSIZE_BYTES) : MY_AES_KEYSIZE_BYTES);
        ullDstFileSize = sizeof(FILE_HEADER) + ullEncryptedBufferSize;

        /*
        * 3a.2 Map destination file in memory. That will also create the file with right size.
        */
        NTSTATUS_API_CHECK_SUCCESS(MyCreateFileMapping(
            wszDstFilepath,
            TRUE,
            ullDstFileSize,
            &dstMappingDesc));

        /*
        * 3a.3. Retrieve a certificate context pointer from recipient's cert hash.
        * Certificate must be in the personal TrustedPeople store.
        */
        NTSTATUS_API_CHECK_SUCCESS(MyGetCertificateCtxFromHash(
            L"TrustedPeople",
            &pRecipientCertContext,
            wszCertHash
        ));

        /*
        * 3a.4 Create the file header for the destination file.
        */
        pFileHeader = (PFILE_HEADER)dstMappingDesc.pMappingStart;
        ZeroMemory(pFileHeader, sizeof(FILE_HEADER));
        pFileHeader->dwMagic = 'EnCr';
        pFileHeader->cbEncryptedRecipientBlob = sizeof(pFileHeader->pbEncryptedRecipientBlob);
        CopyMemory(&pFileHeader->rgbRecipientCertHash[0], wszCertHash, sizeof(pFileHeader->rgbRecipientCertHash));


        /*
        * 3a.5 Set a pointer at the beginning of the encrypted section in the destination file.
        */
        pbEncryptedStart = (LPBYTE)(dstMappingDesc.pMappingStart) + sizeof(FILE_HEADER);
        cbEncryptedStart = dstMappingDesc.ullMappingSize - sizeof(FILE_HEADER);

        /*
        * 3a.6 Encrypt the source file and put the encrypted content into the destination file.
        * Will generate a random symmetric key in keyDescriptor
        */
        NTSTATUS_API_CHECK_SUCCESS(MyEncryptBuffer(
            (PBYTE)srcMappingDesc.pMappingStart,
            srcMappingDesc.ullMappingSize,
            pbEncryptedStart,
            cbEncryptedStart,
            &cbProcessedBytes,
            &keyDescriptor));

        /*
        * 3a.7 Get a handle to the recipient's public key.
        */
        BOOL_API_CHECK_SUCCESS(CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            &pRecipientCertContext->pCertInfo->SubjectPublicKeyInfo,
            0,
            NULL,
            &hRecipientKey));

        /*
        * 3a.8 Encrypt the symetric key material with recipient's public key.
        * Encrypted material is put in the header.
        */
        NTSTATUS_API_CHECK_SUCCESS(BCryptEncrypt(
            hRecipientKey,
            (PUCHAR)&keyDescriptor,
            sizeof(KEY_DESC),
            NULL,
            NULL,
            0,
            pFileHeader->pbEncryptedRecipientBlob,
            pFileHeader->cbEncryptedRecipientBlob,
            &cbEncryptedRecipientBlobSize,
            BCRYPT_PAD_PKCS1));

        /*
        * 3a.9 Adjust the size of the encrypted key material in the header.
        * We had a fixed size previously.
        */
        pFileHeader->cbEncryptedRecipientBlob = cbEncryptedRecipientBlobSize;

        /*
        * 3a.10 flush view of the file.
        */
        BOOL_API_CHECK_SUCCESS(FlushViewOfFile(
            dstMappingDesc.pMappingStart,
            0));

        dwRet = ERROR_SUCCESS;
        
    }  //if (fEncrypt)
    else
    {
        /*
        * We are unprotecting the file.
        * source file: Protected file aka. encrypted content + header
        * destination file: clear text file.
        */

        /*  
        * 3b.1 Set a pointer to our file header
        */
        pFileHeader = (PFILE_HEADER)srcMappingDesc.pMappingStart;

        /*
        * 3b.2 Ensure the file starts with our magic number
        */
        if ('EnCr' != pFileHeader->dwMagic)
        {
            fprintf(stderr, "[%d] - %s - Invalid file header\n", __LINE__, "if ('EnCr' != pFileHeader->dwMagic)");
            goto Cleanup;
        }

        /*
        * 3b.3 Set a pointer to the recipient's certificate hash
        */
        wszCertHash = pFileHeader->rgbRecipientCertHash;

        /*
        * 3b.4 get a reference to the recipient's certificate from the hash.
        * Certificate must be in the Personal certificate store.
        */
        NTSTATUS_API_CHECK_SUCCESS(MyGetCertificateCtxFromHash(
            L"MY",
            &pRecipientCertContext,
            wszCertHash
        ));

        /*
        * 3b.5 Acquire a handle to the certificate's private key.
        */
        BOOL_API_CHECK_SUCCESS(CryptAcquireCertificatePrivateKey(
            pRecipientCertContext,
            CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            NULL,
            &hNCryptKey,
            &dwKeySpec,
            &fMustFreeRecipientKey
        ));


        /*
        * Ensure we get a key from NCrypt.
        */
        if (CERT_NCRYPT_KEY_SPEC != dwKeySpec)
        {
            fprintf(stderr, "[%d] - %s - Invalid key spec\n", __LINE__, "if (CERT_NCRYPT_KEY_SPEC != dwKeySpec)");
            goto Cleanup;
        }

        /*
        * 3b.6 Decrypt the key material using the recipient's certificate.
        */
        NTSTATUS_API_CHECK_SUCCESS(NCryptDecrypt(
            hNCryptKey,
            pFileHeader->pbEncryptedRecipientBlob,
            pFileHeader->cbEncryptedRecipientBlob,
            NULL,
            (PBYTE)&keyDescriptor,
            sizeof(KEY_DESC),
            &cbProcessedBytes,
            NCRYPT_PAD_PKCS1_FLAG
        ));

        /*
        * 3b.7 Compute destination file size (clear text).
        * Just remove size of the header.
        */
        ullDstFileSize = srcMappingDesc.ullMappingSize - sizeof(FILE_HEADER);


        /*
        * 3b.8 Create a file mapping for the destionation file.
        * That will also create the file and set the correct size.
        */
        NTSTATUS_API_CHECK_SUCCESS(MyCreateFileMapping(
            wszDstFilepath,
            TRUE,
            ullDstFileSize,
            &dstMappingDesc));

        /*
        * 3b.9 Set a pointer to the beginning of the encrypted payload in the source file.
        */
        pbEncryptedStart = (LPBYTE)(srcMappingDesc.pMappingStart) + sizeof(FILE_HEADER);
        cbEncryptedStart = srcMappingDesc.ullMappingSize - sizeof(FILE_HEADER);

        /*
        * 3b.10 Decrypt content using the symetric key.
        */
        NTSTATUS_API_CHECK_SUCCESS(MyDecryptBuffer(
            pbEncryptedStart,
            cbEncryptedStart,
            (PBYTE)dstMappingDesc.pMappingStart,
            dstMappingDesc.ullMappingSize,
            &cbProcessedBytes,
            &keyDescriptor
        ));

        /*
        * 3a.11 flush view of the file.
        */
        BOOL_API_CHECK_SUCCESS(FlushViewOfFile(
            dstMappingDesc.pMappingStart,
            0));

        dwRet = ERROR_SUCCESS;

    } //else (fEncrypt)


Cleanup:

    if (dstMappingDesc.hFile)
        MyDeleteFileMapping(&dstMappingDesc);

    if (srcMappingDesc.hFile)
        MyDeleteFileMapping(&srcMappingDesc);

    return dwRet;
}

