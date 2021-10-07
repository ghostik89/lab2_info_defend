#include <iostream>
#include <windows.h>
#include "wincrypt.h"
#include "winerror.h"
    

void sample(){
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
    sample();
    return 0;
}
