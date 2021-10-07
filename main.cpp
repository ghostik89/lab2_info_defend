#include <iostream>
#include <windows.h>
#include "wincrypt.h"
#include "winerror.h"
#include "string"

using namespace std;

BOOL GetExportedKey(
        HCRYPTKEY hKey,
        DWORD dwBlobType,
        LPBYTE *ppbKeyBlob,
        LPDWORD pdwBlobLen)
{
    DWORD dwBlobLength = 12;
    *ppbKeyBlob = NULL;
    *pdwBlobLen = 0;

    // Export the public key. Here the public key is exported to a
    // PUBLICKEYBLOB. This BLOB can be written to a file and
    // sent to another user.

    if(CryptExportKey(
            hKey,
            0,
            dwBlobType,
            0,
            nullptr,
            &dwBlobLength))
    {
        printf("Size of the BLOB for the public key determined. \n");
    }
    else
    {
        printf("Error computing BLOB length.\n");
        return FALSE;
    }

    // Allocate memory for the pbKeyBlob.
    if(*ppbKeyBlob = (LPBYTE)malloc(dwBlobLength))
    {
        printf("Memory has been allocated for the BLOB. \n");
    }
    else
    {
        printf("Out of memory. \n");
        return FALSE;
    }

    // Do the actual exporting into the key BLOB.
    if(CryptExportKey(
            hKey,
            0,
            dwBlobType,
            0,
            *ppbKeyBlob,
            &dwBlobLength))
    {
        printf("Contents have been written to the BLOB. \n");
        *pdwBlobLen = dwBlobLength;
    }
    else
    {
        printf("Error exporting key.\n");
        free(*ppbKeyBlob);
        *ppbKeyBlob = NULL;

        return FALSE;
    }

    return TRUE;
}

BOOL ImportKey(HCRYPTPROV hProv, LPBYTE pbKeyBlob, DWORD dwBlobLen)
{
    HCRYPTKEY hPubKey;

    //---------------------------------------------------------------
    // This code assumes that a cryptographic provider (hProv)
    // has been acquired and that a key BLOB (pbKeyBlob) that is
    // dwBlobLen bytes long has been acquired.

    //---------------------------------------------------------------
    // Get the public key of the user who created the digital
    // signature and import it into the CSP by using CryptImportKey.
    // The key to be imported is in the buffer pbKeyBlob that is
    // dwBlobLen bytes long. This function returns a handle to the
    // public key in hPubKey.

    if(CryptImportKey(
            hProv,
            pbKeyBlob,
            dwBlobLen,
            0,
            0,
            &hPubKey))
    {
        printf("The key has been imported.\n");
    }
    else
    {
        printf("Public key import failed.\n");
        return FALSE;
    }

    //---------------------------------------------------------------
    // Insert code that uses the imported public key here.
    //---------------------------------------------------------------

    //---------------------------------------------------------------
    // When you have finished using the key, you must release it.
    if(CryptDestroyKey(hPubKey))
    {
        printf("The public key has been released.");
    }
    else
    {
        printf("The public key has not been released.");
        return FALSE;
    }

    return TRUE;
}

void init(){
    // Объявление и инициализация переменных.
    HCRYPTPROV hCryptProv = 0;        // дескриптор криптопровайдера
    LPCSTR UserName = "MyKeyContainer";  // название ключевого контейнера
    HCRYPTKEY hKey;    // дескриптор ключа

    //-------------------------------------------------------------------
    // Инициализация криптопровайдера, получение дескриптора криптопровайдера
    if(CryptAcquireContext(
            &hCryptProv,               // дескриптор криптопровайдера
            UserName,                  // название ключевого контейнера
            NULL,                      // используем криптопровайдер по-умолчанию (Microsoft)
            PROV_RSA_FULL,             // тип провайдера
            0))                        // значение флага (выставляется в 0, чтобы предоставить
        // возможность открывать существующий ключевой контейнер)
    {
        printf("A cryptographic context with the %s key container \n",    UserName);
        printf("has been acquired.\n\n");
    }else{
        //-------------------------------------------------------------------
        // Возникла ошибка при инициализации криптопровайдера. Это может
        // означать, что ключевой контейнер не был открыт, либо не существует.
        // В этом случае функция получения дескриптора криптопровайдера может быть
        // вызвана повторно, с измененным значением флага, что позволит создать
        // новый ключевой контейнер.Коды ошибок определены в Winerror.h.
        if (GetLastError() == NTE_BAD_KEYSET){
            if(CryptAcquireContext(&hCryptProv, UserName, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)){
                printf("A new key container has been created.\n");
            }else{
                printf("Could not create a new key container.\n");
                exit(1);
            }
        }else{
            printf("A cryptographic service handle could not be acquired.\n");
            exit(1);
        }
    }// Конец если.

    //-------------------------------------------------------------------
    //  Создание случайного сессионного ключа
    if(CryptGenKey(hCryptProv, CALG_RC4,CRYPT_EXPORTABLE,&hKey)) {
        printf("A session key has been created.\n");
    } else {
        printf("Error during CryptGenKey.\n");
        exit(1);
    }

    //-------------------------------------------------------------------
    // По окончании работы все дескрипторы должны быть удалены.
    if (!CryptDestroyKey(hKey)) {// удаление дескриптора ключа
        printf("Error during CryptDestroyKey.\n");
        exit(1);
    }
    if (CryptReleaseContext(hCryptProv,0)) {// удаление дескриптора криптопровайдера
        printf("The handle has been released.\n");
    } else {
        printf("The handle could not be released.\n");
    }
}

int main() {
    //    init();
    // логин юзера
    // если нет ключа то оставить новый
    // если есть, то считать
    // оставить сообщение для юзера
    // или считать сообщение для юзера
    return 0;
}
