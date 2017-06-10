#ifndef SOFTWARE_RESTRICTION_POLICIES_H
#define SOFTWARE_RESTRICTION_POLICIES_H

#include <windows.h>
#include <mscat.h>
#include "string_list.h"
#include "path_list.h"

class software_restriction_policies {
  public:
    // Constructor.
    software_restriction_policies(bool all_signers);

    // Destructor.
    ~software_restriction_policies();

    // Initialize.
    bool init();

    // Load.
    bool load(const TCHAR* signers,
              const TCHAR* hashes,
              const TCHAR* paths);

    // Allow.
    bool allow(const TCHAR* filename) const;

    // Print signers.
    bool print_signers(const TCHAR* filename) const;

    // Print hash.
    bool print_hash(const TCHAR* filename) const;

  private:
    static const size_t HASH_MAX_LEN = 20;
    static const DWORD SIGNER_INFO_MAX_LEN = 64 * 1024;
    static const DWORD SIGNER_MAX_LEN = 4 * 1024;

    static const GUID driver_action_verify;

    HCATADMIN _M_catalog;

    string_list<wchar_t> _M_signers;
    bool _M_all_signers;

    string_list<BYTE> _M_hashes;

    path_list _M_paths;

    // Load signers.
    bool load_signers(const TCHAR* filename);

    // Load hashes.
    bool load_hashes(const TCHAR* filename);

    // Load paths.
    bool load_paths(const TCHAR* filename);

    // In catalog?
    bool in_catalog(BYTE* hash, DWORD hashlen) const;

    // Is signed?
    bool is_signed(const wchar_t* filename) const;

    // Get signer.
    bool get_signer(HCERTSTORE certificate_store,
                    HCRYPTMSG msg,
                    DWORD idx,
                    wchar_t* signer,
                    DWORD& signerlen) const;

    // Calculate hash.
    bool calculate_hash(const TCHAR* filename,
                        BYTE* hash,
                        DWORD& hashlen) const;
};

#endif // SOFTWARE_RESTRICTION_POLICIES_H
