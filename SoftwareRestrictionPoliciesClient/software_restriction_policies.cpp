#include <stdio.h>
#include "software_restriction_policies.h"
#include <softpub.h>
#include <tchar.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

const GUID software_restriction_policies::driver_action_verify = DRIVER_ACTION_VERIFY;

software_restriction_policies::software_restriction_policies(bool all_signers)
  : _M_catalog(nullptr),
    _M_all_signers(all_signers)
{
}

software_restriction_policies::~software_restriction_policies()
{
  if (_M_catalog) {
    CryptCATAdminReleaseContext(_M_catalog, 0);
  }
}

bool software_restriction_policies::init()
{
  // Acquire handle to catalog.
  return (CryptCATAdminAcquireContext2(&_M_catalog,
                                       &driver_action_verify,
                                       NULL,
                                       NULL,
                                       0) == TRUE);
}

bool software_restriction_policies::load(const TCHAR* signers,
                                         const TCHAR* hashes,
                                         const TCHAR* paths)
{
  return (((_M_all_signers) || (!signers) || (load_signers(signers))) &&
          ((!hashes) || (load_hashes(hashes))) &&
          ((!paths) || (load_paths(paths))));
}

bool software_restriction_policies::allow(const TCHAR* filename) const
{
#ifdef UNICODE
  const WCHAR* tmpfilename = filename;
  size_t len = wcslen(tmpfilename);
#else
  WCHAR path[_MAX_PATH];
  size_t len;
  if (mbstowcs_s(&len, path, _countof(path), filename, _countof(path)) != 0) {
    return false;
  }

  const WCHAR* tmpfilename = path;
#endif

  // If the path is allowed...
  if (_M_paths.find(tmpfilename, len)) {
    return true;
  }

  // If the file is signed...
  if (is_signed(tmpfilename)) {
    return true;
  }

  // Calculate hash.
  BYTE hash[HASH_MAX_LEN];
  DWORD hashlen;
  if (calculate_hash(filename, hash, hashlen)) {
    // If the file is in the catalog...
    if (in_catalog(hash, hashlen)) {
      return true;
    }

    // If the hash is allowed...
    if (_M_hashes.find(hash, hashlen)) {
      return true;
    }
  }

  return false;
}

bool software_restriction_policies::print_signers(const TCHAR* filename) const
{
#ifdef UNICODE
  const WCHAR* tmpfilename = filename;
#else
  WCHAR path[_MAX_PATH];
  size_t len;
  if (mbstowcs_s(&len, path, _countof(path), filename, _countof(path)) != 0) {
    return false;
  }

  const WCHAR* tmpfilename = path;
#endif

  HCERTSTORE certificate_store;
  HCRYPTMSG msg;
  if (CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                       tmpfilename,
                       CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                       CERT_QUERY_FORMAT_FLAG_BINARY,
                       0,
                       NULL,
                       NULL,
                       NULL,
                       &certificate_store,
                       &msg,
                       NULL)) {
    // Get number of signers.
    DWORD nsigners;
    DWORD len = sizeof(DWORD);
    if (CryptMsgGetParam(msg,
                         CMSG_SIGNER_COUNT_PARAM,
                         0,
                         &nsigners,
                         &len)) {
      for (DWORD i = 0; i < nsigners; i++) {
        wchar_t signer[SIGNER_MAX_LEN + 1];
        DWORD signerlen;
        if (get_signer(certificate_store, msg, i, signer, signerlen)) {
          _tprintf(_T("Signer: '%ls'.\n"), signer);
        } else {
          CertCloseStore(certificate_store, 0);
          CryptMsgClose(msg);

          return false;
        }
      }

      CertCloseStore(certificate_store, 0);
      CryptMsgClose(msg);

      return true;
    } else {
      CertCloseStore(certificate_store, 0);
      CryptMsgClose(msg);
    }
  }

  return false;
}

bool software_restriction_policies::print_hash(const TCHAR* filename) const
{
  BYTE hash[HASH_MAX_LEN];
  DWORD hashlen;
  if (calculate_hash(filename, hash, hashlen)) {
    for (DWORD i = 0; i < hashlen; i++) {
      _tprintf(_T("%02x"), hash[i]);
    }

    _tprintf(_T("\n"));

    return true;
  } else {
    return false;
  }
}

bool software_restriction_policies::load_signers(const TCHAR* filename)
{
  // Open file for reading.
  FILE* file;
  if (_tfopen_s(&file, filename, _T("r, ccs=UTF-8")) == 0) {
    // For each line...
    wchar_t line[SIGNER_MAX_LEN + 1];
    while (fgetws(line, _countof(line), file)) {
      // Skip initial blanks (if any).
      const wchar_t* begin = line;
      while ((*begin == L' ') || (*begin == L'\t')) {
        begin++;
      }

      // If not a comment...
      if (*begin != L'#') {
        const wchar_t* ptr = begin;
        const wchar_t* end = begin;
        while ((*ptr) && (*ptr != L'\n')) {
          if (*ptr > L' ') {
            end = ++ptr;
          } else {
            ptr++;
          }
        }

        size_t len;
        if ((len = end - begin) > 0) {
          if (!_M_signers.add(begin, len)) {
            fclose(file);
            return false;
          }
        }
      }
    }

    fclose(file);

    return true;
  }

  return false;
}

bool software_restriction_policies::load_hashes(const TCHAR* filename)
{
  // Open file for reading.
  FILE* file;
  if (_tfopen_s(&file, filename, _T("r")) == 0) {
    // For each line...
    char line[(2 * HASH_MAX_LEN) + 256];
    while (fgets(line, sizeof(line), file)) {
      // If not a comment...
      if (*line != '#') {
        BYTE hash[HASH_MAX_LEN];
        const BYTE* const hashend = hash + sizeof(hash);
        BYTE* out = hash;
        size_t len = 0;

        const char* ptr = line;
        while ((out < hashend) && (*ptr > ' ')) {
          if ((*ptr >= '0') && (*ptr <= '9')) {
            if ((len % 2) == 0) {
              *out = (*ptr - '0') << 4;
            } else {
              *out++ |= (*ptr - '0');
            }
          } else if ((*ptr >= 'a') && (*ptr <= 'f')) {
            if ((len % 2) == 0) {
              *out = (*ptr - 'a' + 10) << 4;
            } else {
              *out++ |= (*ptr - 'a' + 10);
            }
          } else if ((*ptr >= 'A') && (*ptr <= 'F')) {
            if ((len % 2) == 0) {
              *out = (*ptr - 'A' + 10) << 4;
            } else {
              *out++ |= (*ptr - 'A' + 10);
            }
          } else {
            fclose(file);
            return false;
          }

          len++;
          ptr++;
        }

        if (len > 0) {
          if (((len % 2) == 0) && ((*ptr == '\n') || (!*ptr))) {
            if (!_M_hashes.add(hash, out - hash)) {
              fclose(file);
              return false;
            }
          } else {
            fclose(file);
            return false;
          }
        }
      }
    }

    fclose(file);

    return true;
  }

  return false;
}

bool software_restriction_policies::load_paths(const TCHAR* filename)
{
  // Open file for reading.
  FILE* file;
  if (_tfopen_s(&file, filename, _T("r, ccs=UTF-8")) == 0) {
    // For each line...
    wchar_t line[_MAX_PATH + 256];
    while (fgetws(line, _countof(line), file)) {
      // If not a comment...
      if (*line != L'#') {
        const wchar_t* ptr = line;
        while ((*ptr) && (*ptr != L'\n')) {
          ptr++;
        }

        size_t len;
        if ((len = ptr - line) > 0) {
          if (!_M_paths.add(line, len)) {
            fclose(file);
            return false;
          }
        }
      }
    }

    fclose(file);

    return true;
  }

  return false;
}

bool software_restriction_policies::in_catalog(BYTE* hash, DWORD hashlen) const
{
  HCATINFO info;
  if ((info = CryptCATAdminEnumCatalogFromHash(_M_catalog,
                                               hash,
                                               hashlen,
                                               0,
                                               NULL)) != NULL) {
    CryptCATAdminReleaseCatalogContext(_M_catalog, info, 0);

    return true;
  }

  return false;
}

bool software_restriction_policies::is_signed(const wchar_t* filename) const
{
  HCERTSTORE certificate_store;
  HCRYPTMSG msg;
  if (CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                       filename,
                       CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                       CERT_QUERY_FORMAT_FLAG_BINARY,
                       0,
                       NULL,
                       NULL,
                       NULL,
                       &certificate_store,
                       &msg,
                       NULL)) {
    // All signers?
    if (_M_all_signers) {
      CertCloseStore(certificate_store, 0);
      CryptMsgClose(msg);

      return true;
    }

    // Get number of signers.
    DWORD nsigners;
    DWORD len = sizeof(DWORD);
    if (CryptMsgGetParam(msg,
                         CMSG_SIGNER_COUNT_PARAM,
                         0,
                         &nsigners,
                         &len)) {
      for (DWORD i = 0; i < nsigners; i++) {
        wchar_t signer[SIGNER_MAX_LEN + 1];
        DWORD signerlen;
        if (get_signer(certificate_store, msg, i, signer, signerlen)) {
#if _DEBUG
          _tprintf(_T("Filename: '%ls', signer: '%ls'.\n"), filename, signer);
#endif

          if (_M_signers.find(signer, signerlen)) {
            CertCloseStore(certificate_store, 0);
            CryptMsgClose(msg);

            return true;
          }
        } else {
          CertCloseStore(certificate_store, 0);
          CryptMsgClose(msg);

          return false;
        }
      }
    }

    CertCloseStore(certificate_store, 0);
    CryptMsgClose(msg);
  }

  return false;
}

bool software_restriction_policies::get_signer(HCERTSTORE certificate_store,
                                               HCRYPTMSG msg,
                                               DWORD idx,
                                               wchar_t* signer,
                                               DWORD& signerlen) const
{
  UINT8 buf[SIGNER_INFO_MAX_LEN];
  CMSG_SIGNER_INFO* signer_info = reinterpret_cast<CMSG_SIGNER_INFO*>(buf);
  DWORD len = sizeof(buf);

  if (CryptMsgGetParam(msg,
                       CMSG_SIGNER_INFO_PARAM,
                       idx,
                       signer_info,
                       &len)) {
    CERT_INFO cert_info;
    cert_info.Issuer = signer_info->Issuer;
    cert_info.SerialNumber = signer_info->SerialNumber;

    const CERT_CONTEXT* context;
    if ((context = CertFindCertificateInStore(certificate_store,
                                              ENCODING,
                                              0,
                                              CERT_FIND_SUBJECT_CERT,
                                              &cert_info,
                                              NULL)) != NULL) {
      // Get signer name size.
      if (((len = CertGetNameStringW(context,
                                     CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                     0,
                                     NULL,
                                     NULL,
                                     0)) > 1) &&
          (len - 1 <= SIGNER_MAX_LEN)) {
        // Get signer name.
        if (CertGetNameStringW(context,
                               CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               0,
                               NULL,
                               signer,
                               len) > 1) {
          CertFreeCertificateContext(context);

          signerlen = len - 1; // Without trailing '\0'.
          return true;
        }
      }

      CertFreeCertificateContext(context);
    }
  }

  return false;
}

bool software_restriction_policies::calculate_hash(const TCHAR* filename,
                                                   BYTE* hash,
                                                   DWORD& hashlen) const
{
  // Open file for reading.
  HANDLE hFile;
  if ((hFile = CreateFile(filename,
                          GENERIC_READ,
                          FILE_SHARE_READ,
                          NULL,
                          OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL,
                          NULL)) != INVALID_HANDLE_VALUE) {
    // Calculate hash.
    hashlen = HASH_MAX_LEN;
    if (CryptCATAdminCalcHashFromFileHandle2(_M_catalog,
                                             hFile,
                                             &hashlen,
                                             hash,
                                             0)) {
      CloseHandle(hFile);
      return true;
    }

    CloseHandle(hFile);
  }

  return false;
}
