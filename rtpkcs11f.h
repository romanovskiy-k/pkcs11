/*******************************************************************
* Rutoken ECP                                                      *
* Copyright (C) Aktiv Co. 2003-11                                  *
* rtpkcs11f.h                                                      *
* ����, ���������� �������������� ������� ������ � Rutoken ECP �   *
* ���������� PKCS#11.                                              *
********************************************************************/


/* C_EX_GetFunctionListExtended returns the extended function
 * list. */
CK_PKCS11_FUNCTION_INFO(C_EX_GetFunctionListExtended)
#ifdef CK_NEED_ARG_LIST
(
  CK_FUNCTION_LIST_EXTENDED_PTR_PTR ppFunctionList /* receives
                           * pointer to extended function list */
);
#endif


/* C_EX_InitToken initializes a token with full format. */
CK_PKCS11_FUNCTION_INFO(C_EX_InitToken)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_RUTOKEN_INIT_PARAM_PTR pInitInfo /* init parameters */
);
#endif


/* C_EX_GetTokenInfoExtended obtains information about a particular
 * token in the system. */
CK_PKCS11_FUNCTION_INFO(C_EX_GetTokenInfoExtended)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID                 slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_EXTENDED_PTR pInfo    /* receives the token information */
);
#endif


/* C_EX_UnblockUserPIN unblock the blocked user's PIN.
 * C_EX_UnblockUserPIN requires same conditions as a
 * C_InitPIN */
CK_PKCS11_FUNCTION_INFO(C_EX_UnblockUserPIN)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession   /* the session's handle */
);
#endif


/* C_EX_SetTokenName modifies the token symbol name (label) if
 * User is logged in. C_EX_SetTokenName can only be called in
 * the "R/W User Functions" state.
 */
CK_PKCS11_FUNCTION_INFO(C_EX_SetTokenName)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pLabel,    /* the new label */
  CK_ULONG          ulLabelLen /* length of the new label */
);
#endif


/* C_EX_SetLicense modifies the token license if User or SO
 * is logged in. C_EX_SetLicense can only be called in the
 * "R/W User Functions" state or "R/W SO Functions" state.
 * hSession [in] - the session's handle
 * ulLicenseNum [in] - number of the new license, can only be 1 or 2
 * pLicense [in] - byte buffer with the data of new license
 * ulLicenseLen [in] - length of the new license, can only be 72
 */
CK_PKCS11_FUNCTION_INFO(C_EX_SetLicense)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_ULONG          ulLicenseNum, /* the number of the new license */
  CK_BYTE_PTR       pLicense,     /* the new license */
  CK_ULONG          ulLicenseLen  /* length of the new license */
);
#endif


/* C_EX_GetLicense read the token license. C_EX_GetLicense
 * can be called in the every state.
 * hSession [in] - the session's handle
 * ulLicenseNum [in] - number of the license, can only be 1 or 2
 * pLicense [out] - byte buffer for data of license, length of the
 *                  buffer can only be not less then license length
 * pulLicenseLen [in/out] - [in]- sets license length, can only be 72
 *                         [out] - gets license length (if pLicense
 *                                 is NULL_PTR)
 */
CK_PKCS11_FUNCTION_INFO(C_EX_GetLicense)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_ULONG          ulLicenseNum, /* the number of the license */
  CK_BYTE_PTR       pLicense,     /* receives the license */
  CK_ULONG_PTR      pulLicenseLen /* length of the license */
);
#endif


/* C_EX_GetCertificateInfoText get text information about
 * certificate. C_EX_GetCertificateInfoText can be called
 * in the every state.
 * hSession [in] - the session's handle
 * hObject [in] - the object's (certificate) handle
 * pInfo [out] - return address of allocated buffer with
 *               text information
 * pulInfoLen [out] - get size of allocated buffer
 */
CK_PKCS11_FUNCTION_INFO(C_EX_GetCertificateInfoText)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hCert,     /* the object's handle */
  CK_CHAR_PTR       *pInfo,    /* receives the information */
  CK_ULONG_PTR      pulInfoLen /* length of the license buffer */
);
#endif


/* C_EX_PKCS7Sign sign data and pack it to PKCS#7 format
 * certificate. C_EX_PKCS7Sign can only be called in the
 * "R/W User Functions" or "R User Functions" state.
 */
CK_PKCS11_FUNCTION_INFO(C_EX_PKCS7Sign)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_OBJECT_HANDLE  hCert,
  CK_BYTE_PTR       *ppEnvelope,
  CK_ULONG_PTR      pEnvelopeLen,
  CK_OBJECT_HANDLE  hPrivKey,
  CK_OBJECT_HANDLE_PTR phCertificates,
  CK_ULONG          ulCertificatesLen,
  CK_ULONG          flags
);
#endif


/* C_EX_CreateCSR create request by certificate and pack it in
 * PKCS#10 format. C_EX_CreateCSR can only be called in the
 * "R/W User Functions" or "R User Functions" state.
 */
CK_PKCS11_FUNCTION_INFO(C_EX_CreateCSR)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hPublicKey,
  CK_CHAR_PTR       *dn,
  CK_ULONG          dnLength,
  CK_BYTE_PTR       *pCsr,
  CK_ULONG_PTR      pulCsrLength,
  CK_OBJECT_HANDLE  hPrivKey,
  CK_CHAR_PTR       *pAttributes,
  CK_ULONG          ulAttributesLength,
  CK_CHAR_PTR       *pExtensions,
  CK_ULONG          ulExtensionsLength
);
#endif


/* C_EX_FreeBuffer free buffer, allocated in extended functions.
 * pBuffer [in] - pointer to the buffer
 */
CK_PKCS11_FUNCTION_INFO(C_EX_FreeBuffer)
#ifdef CK_NEED_ARG_LIST
(
  CK_BYTE_PTR       pBuffer /* pointer to the buffer */
);
#endif


/* C_EX_GetTokenName return the token symbol name (label).
 * hSession [in] - the session's handle
 * pLabel [out] - byte buffer for label
 * pulLabelLen [in/out] - [in]- sets buffer length
 *                        [out] - gets label length
 */
CK_PKCS11_FUNCTION_INFO(C_EX_GetTokenName)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_CHAR_PTR       pLabel,     /* the label */
  CK_ULONG_PTR      pulLabelLen /* length of the label */
);
#endif


/* C_EX_SetLocalPIN modifies the local PIN for devices witch supported it.
 * slotID [in] - ID of the token's slot
 * pUserPin [in] - the current User PIN
 * ulUserPinLen [in] - length of current User PIN
 * pNewLocaPin [in] - the new local PIN
 * ulNewLocaPinLen [in] - length of the new local PIN
 * ulLocalID [in] - ID of the local PIN
 */
CK_PKCS11_FUNCTION_INFO(C_EX_SetLocalPIN)
#ifdef CK_NEED_ARG_LIST
(
  CK_SLOT_ID  slotID,           /* ID of the token's slot */
  CK_UTF8CHAR_PTR pUserPin,     /* the current User PIN */
  CK_ULONG    ulUserPinLen,     /* length of current User PIN */
  CK_UTF8CHAR_PTR pNewLocalPin, /* the new local PIN */
  CK_ULONG    ulNewLocalPinLen, /* length of the new local PIN */
  CK_ULONG    ulLocalID         /* ID of the local PIN */
);
#endif

