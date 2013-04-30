/************************************************************************
* Rutoken ECP                                                           *
* Copyright (C) Aktiv Co. 2003-10                                       *
* rtRusPKCS11.h                                                         * 
* ����, ���������� ��� ������� ��� ������ � ����������� PKCS#11,        *
* � ����� ���������� ��� ���������� ������ �� ��������� TK-26           *
*                                                                       *
* !!! ���������� � ���� rtpkcs11t.h                                     *
************************************************************************/

#ifndef __RTRUSPKCS11_H__
#define __RTRUSPKCS11_H__

#if 0

#include "cryptoki.h"

#ifdef _WIN32
#pragma pack(push, rtruspkcs11, 1)
#endif

/*
* NSSCK_VENDOR_???
* ������� VENDOR_DEFINED-�������� - ���������� ������� ���
* �������� ������������ ������������ ����� �������� - ���������� "����"
*/
#define NSSCK_VENDOR_PKSC11_RU_TEAM 0xd4321000 /* 0x80000000 | 0x54321000 */

/* GOST KEY TYPES */
#define CKK_GOSTR3410					0x00000030
#define CKK_GOSTR3411					0x00000031
#define CKK_GOST28147					0x00000032
/*
#define CKK_GOSTR3410					(NSSCK_VENDOR_PKSC11_RU_TEAM |0x000)
#define CKK_GOSTR3411					(NSSCK_VENDOR_PKSC11_RU_TEAM |0x001)
#define CKK_GOST28147					(NSSCK_VENDOR_PKSC11_RU_TEAM |0x002)
*/

/* GOST OBJECT ATTRIBUTES */
#define CKA_GOSTR3410_PARAMS			0x00000250
#define CKA_GOSTR3411_PARAMS			0x00000251
#define CKA_GOST28147_PARAMS			0x00000252
/*
#define CKA_GOSTR3410PARAMS				(NSSCK_VENDOR_PKSC11_RU_TEAM |0x001)
#define CKA_GOSTR3411PARAMS				(NSSCK_VENDOR_PKSC11_RU_TEAM |0x002)
#define CKA_GOST28147PARAMS				(NSSCK_VENDOR_PKSC11_RU_TEAM |0x003)
*/

/* GOST MECHANISMS */
#define CKM_GOSTR3410_KEY_PAIR_GEN		0x00001200
#define CKM_GOSTR3410					0x00001201
#define CKM_GOSTR3410_WITH_GOSTR3411	0x00001202
#define CKM_GOSTR3410_KEY_WRAP			0x00001203
#define CKM_GOSTR3410_DERIVE			0x00001204
#define CKM_GOSTR3411					0x00001210
#define CKM_GOSTR3411_HMAC				0x00001211 
#define CKM_GOST28147_KEY_GEN			0x00001220
#define CKM_GOST28147_ECB				0x00001221
#define CKM_GOST28147					0x00001222
#define CKM_GOST28147_MAC				0x00001223
#define CKM_GOST28147_KEY_WRAP			0x00001224
/*
#define CKM_GOSTR3410_KEY_PAIR_GEN		(NSSCK_VENDOR_PKSC11_RU_TEAM |0x000)
#define CKM_GOSTR3410					(NSSCK_VENDOR_PKSC11_RU_TEAM |0x001)
#define CKM_GOSTR3410_WITH_GOSTR3411	(NSSCK_VENDOR_PKSC11_RU_TEAM |0x002)
#define CKM_GOSTR3410_KEY_WRAP			(NSSCK_VENDOR_PKSC11_RU_TEAM |0x003)
#define CKM_GOSTR3410_DERIVE			(NSSCK_VENDOR_PKSC11_RU_TEAM |0x004)
#define CKM_GOSTR3411					(NSSCK_VENDOR_PKSC11_RU_TEAM |0x010)
#define CKM_GOSTR3411_HMAC				(NSSCK_VENDOR_PKSC11_RU_TEAM |0x011)
#define CKM_GOST28147_KEY_GEN			(NSSCK_VENDOR_PKSC11_RU_TEAM |0x020)
#define CKM_GOST28147_ECB				(NSSCK_VENDOR_PKSC11_RU_TEAM |0x021)
#define CKM_GOST28147					(NSSCK_VENDOR_PKSC11_RU_TEAM |0x022)
#define CKM_GOST28147_MAC				(NSSCK_VENDOR_PKSC11_RU_TEAM |0x023)
#define CKM_GOST28147_KEY_WRAP			(NSSCK_VENDOR_PKSC11_RU_TEAM |0x023)
*/
#define CKM_TLS_GOST_PRF				(NSSCK_VENDOR_PKSC11_RU_TEAM |0x030)
#define CKM_TLS_GOST_PRE_MASTER_KEY_GEN (NSSCK_VENDOR_PKSC11_RU_TEAM |0x031)
#define CKM_TLS_GOST_MASTER_KEY_DERIVE  (NSSCK_VENDOR_PKSC11_RU_TEAM |0x032)

#define CKM_TLS_GOST_KEY_AND_MAC_DERIVE (NSSCK_VENDOR_PKSC11_RU_TEAM |0x033)
#define CKD_CPDIVERSIFY_KDF				0x00000009
/*
#define CKD_CPDIVERSIFY_KDF				(NSSCK_VENDOR_PKSC11_RU_TEAM |0x001)
*/
#define CKP_PKCS5_PBKD2_HMAC_GOSTR3411  (NSSCK_VENDOR_PKSC11_RU_TEAM |0x001)

typedef CK_ULONG CK_EC_KDF_TYPE;  // !!!!!!!!!!!!!!!!!!!!!! from pkcs11t.h 

typedef struct CK_GOSTR3410_KEY_WRAP_PARAMS {
	CK_BYTE_PTR pWrapOID;
	CK_ULONG ulWrapOIDLen;
	CK_BYTE_PTR pUKM;
	CK_ULONG ulUKMLen;
	CK_OBJECT_HANDLE hKey;
} CK_GOSTR3410_KEY_WRAP_PARAMS;
typedef CK_GOSTR3410_KEY_WRAP_PARAMS CK_PTR CK_GOSTR3410_KEY_WRAP_PARAMS_PTR;

typedef struct CK_GOSTR3410_DERIVE_PARAMS {
	CK_EC_KDF_TYPE kdf;
	CK_BYTE_PTR pPublicData;
	CK_ULONG ulPublicDataLen;
	CK_BYTE_PTR pUKM;
	CK_ULONG ulUKMLen;
} CK_GOSTR3410_DERIVE_PARAMS;
typedef CK_GOSTR3410_DERIVE_PARAMS CK_PTR CK_GOSTR3410_DERIVE_PARAMS_PTR;

/*
typedef struct CK_TLS_GOST_PRF_PARAMS {
	CK_TLS_PRF_PARAMS TlsPrfParams;
	CK_BYTE_PTR pHashParamsOID;
	CK_ULONG ulHashParamsOIDLen;
} CK_TLS_GOST_PRF_PARAMS;
typedef CK_TLS_GOST_PRF_PARAMS CK_PTR CK_TLS_GOST_PRF_PARAMS_PTR;

typedef struct CK_TLS_GOST_MASTER_KEY_DERIVE_PARAMS {
	CK_SSL3_RANDOM_DATA RandomInfo;
	CK_BYTE_PTR pHashParamsOID;
	CK_ULONG ulHashParamsOIDLen;
} CK_TLS_GOST_MASTER_KEY_DERIVE_PARAMS;
typedef CK_TLS_GOST_MASTER_KEY_DERIVE_PARAMS CK_PTR CK_TLS_GOST_MASTER_KEY_DERIVE_PARAMS_PTR;

typedef struct CK_TLS_GOST_KEY_MAT_PARAMS {
	CK_SSL3_KEY_MAT_PARAMS KeyMatParams;
	CK_BYTE_PTR pHashParamsOID;
	CK_ULONG ulHashParamsOIDLen;
} CK_TLS_GOST_KEY_MAT_PARAMS;
typedef CK_TLS_GOST_KEY_MAT_PARAMS CK_PTR CK_TLS_GOST_KEY_MAT_PARAMS_PTR;
*/

#ifdef _WIN32
#pragma pack(pop, rtruspkcs11)
#endif

#endif // 0

#endif /* __RTRUSPKCS11_H__ */


