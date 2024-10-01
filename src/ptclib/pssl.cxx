/*
 * pssl.cxx
 *
 * SSL implementation for PTLib using the SSLeay package
 *
 * Portable Windows Library
 *
 * Copyright (c) 1993-2002 Equivalence Pty. Ltd.
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is Portable Windows Library.
 *
 * The Initial Developer of the Original Code is Equivalence Pty. Ltd.
 *
 * Contributor(s): ______________________________________.
 *
 * Portions bsed upon the file crypto/buffer/bss_sock.c 
 * Original copyright notice appears below
 */

/* crypto/buffer/bss_sock.c */
/* Copyright (C) 1995-1996 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 * 
 * This file is part of an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL
 * specification.  This library and applications are
 * FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the following conditions are aheared to.
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.  If this code is used in a product,
 * Eric Young should be given attribution as the author of the parts used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Eric Young (eay@mincom.oz.au)
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifdef __GNUC__
#pragma implementation "pssl.h"
#endif

#include <ptlib.h>

#include <ptclib/pssl.h>
#include <ptclib/mime.h>

#if P_SSL

#define USE_SOCKETS

extern "C" {

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

#ifdef P_SSL_AES
  #include <openssl/aes.h>
#endif
};

#if (OPENSSL_VERSION_NUMBER < 0x0090819fL)
  #error OpenSSL too old!
#endif

#ifdef _MSC_VER
  #pragma comment(lib, P_SSL_LIB1)
  #pragma comment(lib, P_SSL_LIB2)
#endif


// On Windows, use a define from the header to guess the API type
#ifdef _WIN32
  #include <wincrypt.h>
  #include <cryptuiapi.h>
  #undef X509_NAME
  #pragma comment (lib, "crypt32.lib")
  #pragma comment (lib, "cryptui.lib")

  #ifdef SSL_OP_NO_QUERY_MTU
    #define P_SSL_USE_CONST 1
  #endif
#endif

#define PTraceModule() "SSL"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
  __inline unsigned char * EVP_CIPHER_CTX_iv(EVP_CIPHER_CTX * ctx) { return ctx->iv; }
  __inline void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) { if(p)*p=dh->p; if(q)*q=dh->q; if(g)*g=dh->g; }
  __inline void DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g) { dh->p = p; dh->q = q; dh->g = g; }
  __inline void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key) { if(pub_key)*pub_key=dh->pub_key; if(priv_key)*priv_key=dh->priv_key; }
  __inline void DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key) { dh->pub_key = pub_key; dh->priv_key = priv_key; }
  typedef BIO_METHOD * BIO_METHOD_PTR;
  __inline BIO_METHOD *BIO_meth_new(int type, const char *name) { BIO_METHOD * biom = new BIO_METHOD(); memset(biom, 0, sizeof(*biom)); biom->type = type; biom->name = name; return biom; }
  __inline void BIO_meth_free(BIO_METHOD *biom) { delete biom; }
  __inline void BIO_meth_set_write(BIO_METHOD *biom, int (*write) (BIO *, const char *, int)) { biom->bwrite = write; }
  __inline void BIO_meth_set_read(BIO_METHOD *biom, int (*read) (BIO *, char *, int)) { biom->bread = read;  }
  __inline void BIO_meth_set_ctrl(BIO_METHOD *biom, long (*ctrl) (BIO *, int, long, void *)) { biom->ctrl = ctrl;  }
  __inline void BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy) (BIO *)) { biom->destroy = destroy;  }
  __inline int BIO_get_init(const BIO * bio) { return bio->init; }
  __inline void BIO_set_init(BIO * bio, int init) { bio->init = init; }
  __inline int BIO_get_shutdown(const BIO * bio) { return bio->shutdown; }
  __inline void BIO_set_shutdown(BIO * bio, int shutdown) { bio->shutdown = shutdown; }
  __inline void * BIO_get_data(const BIO * bio) { return bio->ptr; }
  __inline void BIO_set_data(BIO * bio, void * data) { bio->ptr = data; }
#else
  typedef BIO_METHOD const * BIO_METHOD_PTR;
#endif

class PSSLInitialiser : public PProcessStartup
{
  PCLASSINFO(PSSLInitialiser, PProcessStartup)
  public:
    virtual void OnStartup();
    virtual void OnShutdown();

    PFACTORY_GET_SINGLETON(PProcessStartupFactory, PSSLInitialiser);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    static unsigned long ThreadIdCallback()
    {
      return PThread::GetCurrentUniqueIdentifier();
    }

    static void StaticLockingCallback(int mode, int n, const char *, int)
    {
      PSSLInitialiser::GetInstance().LockingCallback(mode, n);
    }

    void LockingCallback(int mode, int n)
    {
      if ((mode & CRYPTO_LOCK) != 0)
        mutexes[n].Wait();
      else
        mutexes[n].Signal();
    }

  private:
    vector<PMutex> mutexes;
#endif
};

PFACTORY_CREATE_SINGLETON(PProcessStartupFactory, PSSLInitialiser);


static PString PSSLError(unsigned long err = ERR_peek_error())
{
  char buf[200];
  ERR_error_string_n(err, buf, sizeof(buf));
  if (buf[0] == '\0')
    sprintf(buf, "code=%lu", err);
  return buf;
}

#define PSSLAssert(prefix) PAssertAlways(prefix + PSSLError())


///////////////////////////////////////////////////////////////////////////////

class PSSL_BIO
{
  public:
    PSSL_BIO(BIO_METHOD_PTR method = BIO_s_file())
      { bio = BIO_new(method); }

    ~PSSL_BIO()
      { BIO_free(bio); }

    operator BIO*() const
      { return bio; }

    bool OpenRead(const PFilePath & filename)
      { return BIO_read_filename(bio, (char *)(const char *)filename) > 0; }

    bool OpenWrite(const PFilePath & filename)
      { return BIO_write_filename(bio, (char *)(const char *)filename) > 0; }

    bool OpenAppend(const PFilePath & filename)
      { return BIO_append_filename(bio, (char *)(const char *)filename) > 0; }

  protected:
    BIO * bio;
};


#define new PNEW


///////////////////////////////////////////////////////////////////////////////

static int PasswordCallback(char *buf, int size, int rwflag, void *userdata)
{
  if (!PAssert(userdata != NULL, PLogicError))
    return 0;

  PSSLPasswordNotifier & notifier = *reinterpret_cast<PSSLPasswordNotifier *>(userdata);
  if (!PAssert(!notifier.IsNULL(), PLogicError))
    return 0;

  PString password;
  notifier(password, rwflag != 0);

  int len = password.GetLength()+1;
  if (len > size)
    len = size;
  memcpy(buf, password.GetPointer(), len); // Include '\0'
  return len-1;
}


///////////////////////////////////////////////////////////////////////////////

PSSLPrivateKey::PSSLPrivateKey()
  : m_pkey(NULL)
{
}


PSSLPrivateKey::PSSLPrivateKey(unsigned modulus,
                               void (*callback)(int,int,void *),
                               void *cb_arg)
  : m_pkey(NULL)
{
  Create(modulus, callback, cb_arg);
}


PSSLPrivateKey::PSSLPrivateKey(const PFilePath & keyFile, PSSLFileTypes fileType)
  : m_pkey(NULL)
{
  Load(keyFile, fileType);
}


PSSLPrivateKey::PSSLPrivateKey(const BYTE * keyData, PINDEX keySize)
  : m_pkey(NULL)
{
  SetData(PBYTEArray(keyData, keySize, false));
}


PSSLPrivateKey::PSSLPrivateKey(const PBYTEArray & keyData)
  : m_pkey(NULL)
{
  SetData(keyData);
}


PSSLPrivateKey::PSSLPrivateKey(const PSSLPrivateKey & privKey)
{
  SetData(privKey.GetData());
}


PSSLPrivateKey::PSSLPrivateKey(evp_pkey_st * privKey, bool duplicate)
{
  if (privKey == NULL || !duplicate)
    m_pkey = privKey;
  else {
    m_pkey = privKey;
    PBYTEArray data = GetData();
    m_pkey = NULL;
    SetData(data);
  }
}


PSSLPrivateKey & PSSLPrivateKey::operator=(const PSSLPrivateKey & privKey)
{
  if (this != &privKey) {
    FreePrivateKey();
    m_pkey = privKey.m_pkey;
  }
  return *this;
}


PSSLPrivateKey & PSSLPrivateKey::operator=(evp_pkey_st * privKey)
{
  if (m_pkey != privKey) {
    FreePrivateKey();
    m_pkey = privKey;
  }
  return *this;
}


PSSLPrivateKey::~PSSLPrivateKey()
{
  FreePrivateKey();
}


void PSSLPrivateKey::FreePrivateKey()
{
  if (m_pkey != NULL) {
    EVP_PKEY_free(m_pkey);
    m_pkey = NULL;
  }
}


void PSSLPrivateKey::Attach(evp_pkey_st * key)
{
  FreePrivateKey();
  m_pkey = key;
}


PBoolean PSSLPrivateKey::Create(unsigned modulus,
                            void (*callback)(int,int,void *),
                            void *cb_arg)
{
  FreePrivateKey();

  if (!PAssert(modulus >= 384, PInvalidParameter))
    return false;

  m_pkey = EVP_PKEY_new();
  if (m_pkey == NULL)
    return false;

  if (EVP_PKEY_assign_RSA(m_pkey, RSA_generate_key(modulus, 0x10001, callback, cb_arg)))
    return true;

  FreePrivateKey();
  return false;
}


bool PSSLPrivateKey::SetData(const PBYTEArray & keyData)
{
  FreePrivateKey();

  const BYTE * keyPtr = keyData;
#if P_SSL_USE_CONST
  m_pkey = d2i_AutoPrivateKey(NULL, &keyPtr, keyData.GetSize());
#else
  m_pkey = d2i_AutoPrivateKey(NULL, (BYTE **)&keyPtr, keyData.GetSize());
#endif

  return m_pkey != NULL;
}


PBYTEArray PSSLPrivateKey::GetData() const
{
  PBYTEArray data;

  if (m_pkey != NULL) {
    BYTE * keyPtr = data.GetPointer(i2d_PrivateKey(m_pkey, NULL));
    i2d_PrivateKey(m_pkey, &keyPtr);
  }

  return data;
}


PString PSSLPrivateKey::AsString() const
{
  return PBase64::Encode(GetData());
}


bool PSSLPrivateKey::Parse(const PString & keyStr)
{
  PBYTEArray keyData;
  return PBase64::Decode(keyStr, keyData) && SetData(keyData);
}


PBoolean PSSLPrivateKey::Load(const PFilePath & keyFile, PSSLFileTypes fileType, const PSSLPasswordNotifier & notifier)
{
  FreePrivateKey();

  PSSL_BIO in;
  if (!in.OpenRead(keyFile)) {
    PTRACE(2, "Could not open private key file \"" << keyFile << '"');
    return false;
  }

  pem_password_cb *cb;
  void *ud;
  if (notifier.IsNULL()) {
    cb = NULL;
    ud = NULL;
  }
  else {
    cb = PasswordCallback;
    ud = (void *)&notifier;
  }

  switch (fileType) {
    case PSSLFileTypeASN1 :
      m_pkey = d2i_PrivateKey_bio(in, NULL);
      if (m_pkey != NULL)
        break;

      PTRACE(2, "Invalid ASN.1 private key file \"" << keyFile << '"');
      return false;

    case PSSLFileTypePEM :
      m_pkey = PEM_read_bio_PrivateKey(in, NULL, cb, ud);
      if (m_pkey != NULL)
        break;

      PTRACE(2, "Invalid PEM private key file \"" << keyFile << '"');
      return false;

    default :
      m_pkey = PEM_read_bio_PrivateKey(in, NULL, cb, ud);
      if (m_pkey != NULL)
        break;

      m_pkey = d2i_PrivateKey_bio(in, NULL);
      if (m_pkey != NULL)
        break;

      PTRACE(2, "Invalid private key file \"" << keyFile << '"');
      return false;
  }

  PTRACE(4, "Loaded private key file \"" << keyFile << '"');
  return true;
}


PBoolean PSSLPrivateKey::Save(const PFilePath & keyFile, PBoolean append, PSSLFileTypes fileType)
{
  if (m_pkey == NULL)
    return false;

  PSSL_BIO out;
  if (!(append ? out.OpenAppend(keyFile) : out.OpenWrite(keyFile))) {
    PTRACE(2, "Could not " << (append ? "append to" : "create") << " private key file \"" << keyFile << '"');
    return false;
  }

  if (fileType == PSSLFileTypeDEFAULT)
    fileType = keyFile.GetType() == ".der" ? PSSLFileTypeASN1 : PSSLFileTypePEM;

  switch (fileType) {
    case PSSLFileTypeASN1 :
      if (i2d_PrivateKey_bio(out, m_pkey))
        return true;
      break;

    case PSSLFileTypePEM :
      if (PEM_write_bio_PrivateKey(out, m_pkey, NULL, NULL, 0, 0, NULL))
        return true;
      break;

    default :
      PAssertAlways(PInvalidParameter);
      return false;
  }

  PTRACE(2, "Error writing certificate file \"" << keyFile << '"');
  return false;
}


///////////////////////////////////////////////////////////////////////////////

PSSLCertificate::PSSLCertificate()
  : m_certificate(NULL)
{
}


PSSLCertificate::PSSLCertificate(const PFilePath & certFile, PSSLFileTypes fileType)
  : m_certificate(NULL)
{
  Load(certFile, fileType);
}


PSSLCertificate::PSSLCertificate(const BYTE * certData, PINDEX certSize)
  : m_certificate(NULL)
{
  SetData(PBYTEArray(certData, certSize, false));
}


PSSLCertificate::PSSLCertificate(const PBYTEArray & certData)
  : m_certificate(NULL)
{
  SetData(certData);
}


PSSLCertificate::PSSLCertificate(const PString & certStr)
  : m_certificate(NULL)
{
  Parse(certStr);
}


PSSLCertificate::PSSLCertificate(const PSSLCertificate & cert)
{
  if (cert.m_certificate == NULL)
    m_certificate = NULL;
  else
    m_certificate = X509_dup(cert.m_certificate);
}


PSSLCertificate::PSSLCertificate(x509_st * cert, bool duplicate)
{
  if (cert == NULL)
    m_certificate = NULL;
  else if (duplicate)
    m_certificate = X509_dup(cert);
  else
    m_certificate = cert;
}


PSSLCertificate & PSSLCertificate::operator=(const PSSLCertificate & cert)
{
  if (this != &cert) {
    FreeCertificate();

    if (cert.m_certificate != NULL)
      m_certificate = X509_dup(cert.m_certificate);
  }
  return *this;
}


PSSLCertificate & PSSLCertificate::operator=(x509_st * cert)
{
  if (m_certificate !=  cert) {
    FreeCertificate();

    if (cert != NULL)
      m_certificate = X509_dup(cert);
  }
  return *this;
}


PSSLCertificate::~PSSLCertificate()
{
  FreeCertificate();
}


void PSSLCertificate::FreeCertificate()
{
  if (m_certificate != NULL) {
    X509_free(m_certificate);
    m_certificate = NULL;

    for (X509_Chain::iterator it = m_chain.begin(); it != m_chain.end(); ++it)
      X509_free(*it);
    m_chain.clear();
  }
}


void PSSLCertificate::Attach(x509_st * cert)
{
  if (m_certificate != cert) {
    FreeCertificate();
    m_certificate = cert;
  }
}


bool PSSLCertificate::CreateRoot(const PString & subject,
                                 const PSSLPrivateKey & privateKey,
                                 const char * digest,
                                 unsigned version)
{
  FreeCertificate();

  if (!privateKey.IsValid()) {
    PTRACE(1, "Cannot create root certiicate: invalid private key");
    return false;
  }

  const EVP_MD * pDigest;
  if (digest == NULL)
    pDigest = EVP_sha1();
  else {
    pDigest = EVP_get_digestbyname(digest);
    if (pDigest == NULL) {
      PTRACE(1, "Cannot create root certiicate: invalid digest algorithm \"" << digest << '"');
      return false;
    }
  }

  POrdinalToString info;
  PStringArray fields = subject.Tokenise('/', false);
  PINDEX i;
  for (i = 0; i < fields.GetSize(); i++) {
    PString field = fields[i];
    PINDEX equals = field.Find('=');
    if (equals != P_MAX_INDEX) {
      int nid = OBJ_txt2nid((char *)(const char *)field.Left(equals));
      if (nid != NID_undef)
        info.SetAt(nid, field.Mid(equals+1));
    }
  }
  if (info.IsEmpty()) {
    PTRACE(1, "Cannot create root certiicate: invalid subject \"" << subject << '"');
    return false;
  }

  m_certificate = X509_new();
  if (PAssertNULL(m_certificate) == NULL)
    return false;

  if (version == 0)
    version = 2;

  if (X509_set_version(m_certificate, version) == 0)
    PTRACE(1, "Cannot create root certiicate: invalid version " << version);
  else {
    {
      static PMutex s_mutex;
      PWaitAndSignal lock(s_mutex);
      static map<PString, long> s_sequenceNumbers;
      ASN1_INTEGER_set(X509_get_serialNumber(m_certificate), ++s_sequenceNumbers[subject]);
    }

    X509_NAME * name = X509_NAME_new();
    for (POrdinalToString::iterator it = info.begin(); it != info.end(); ++it)
      X509_NAME_add_entry_by_NID(name,
                                 it->first,
                                 MBSTRING_ASC,
                                 (unsigned char *)(const char *)it->second,
                                 -1,-1, 0);
    X509_set_issuer_name(m_certificate, name);
    X509_set_subject_name(m_certificate, name);
    X509_NAME_free(name);

    X509_gmtime_adj(X509_get_notBefore(m_certificate), 0);
    X509_gmtime_adj(X509_get_notAfter(m_certificate), (long)60*60*24*365*5);

    X509_PUBKEY * pubkey = X509_PUBKEY_new();
    if (pubkey != NULL) {
      X509_PUBKEY_set(&pubkey, privateKey);
      EVP_PKEY * pkey = X509_PUBKEY_get(pubkey);
      X509_set_pubkey(m_certificate, pkey);
      EVP_PKEY_free(pkey);
      X509_PUBKEY_free(pubkey);

      if (X509_sign(m_certificate, privateKey, pDigest) > 0)
        return true;

      PTRACE(1, "Cannot sign root certificate: " << PSSLError());
    }
  }

  FreeCertificate();
  return false;
}


bool PSSLCertificate::SetData(const PBYTEArray & certData)
{
  FreeCertificate();

  const BYTE * certPtr = certData;
#if P_SSL_USE_CONST
  m_certificate = d2i_X509(NULL, &certPtr, certData.GetSize());
#else
  m_certificate = d2i_X509(NULL, (unsigned char **)&certPtr, certData.GetSize());
#endif
  return m_certificate != NULL;
}


PBYTEArray PSSLCertificate::GetData() const
{
  PBYTEArray data;

  if (m_certificate != NULL) {
    BYTE * certPtr = data.GetPointer(i2d_X509(m_certificate, NULL));
    i2d_X509(m_certificate, &certPtr);
  }

  return data;
}


PString PSSLCertificate::AsString() const
{
  return PBase64::Encode(GetData());
}


bool PSSLCertificate::Parse(const PString & certStr)
{
  PBYTEArray certData;
  return PBase64::Decode(certStr, certData) && SetData(certData);
}


PBoolean PSSLCertificate::Load(const PFilePath & certFile, PSSLFileTypes fileType)
{
  if (fileType == PSSLFileTypeDEFAULT)
    return Load(certFile, PSSLFileTypePEM) || Load(certFile, PSSLFileTypeASN1);

  FreeCertificate();

  PSSL_BIO in;
  if (!in.OpenRead(certFile)) {
    PTRACE(2, "Could not open certificate file \"" << certFile << '"');
    return false;
  }

  X509 * ca;

  switch (fileType) {
    case PSSLFileTypeASN1 :
      m_certificate = d2i_X509_bio(in, NULL);
      if (m_certificate != NULL)
        break;

      PTRACE(2, "Invalid ASN.1 certificate file \"" << certFile << '"');
      return false;

    case PSSLFileTypePEM :
      m_certificate = PEM_read_bio_X509(in, NULL, NULL, NULL);
      if (m_certificate == NULL) {
        PTRACE(2, "Invalid PEM certificate file \"" << certFile << '"');
        return false;
      }
      while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL)
        m_chain.push_back(ca);
      break;

    default :
      PTRACE(2, "Unsupported certificate file \"" << certFile << '"');
      return false;
  }

  PTRACE(4, "Loaded certificate file \"" << certFile << '"');
  return true;
}


PBoolean PSSLCertificate::Save(const PFilePath & certFile, PBoolean append, PSSLFileTypes fileType)
{
  if (m_certificate == NULL)
    return false;

  PSSL_BIO out;
  if (!(append ? out.OpenAppend(certFile) : out.OpenWrite(certFile))) {
    PTRACE(2, "Could not " << (append ? "append to" : "create") << " certificate file \"" << certFile << '"');
    return false;
  }

  if (fileType == PSSLFileTypeDEFAULT)
    fileType = certFile.GetType() == ".der" ? PSSLFileTypeASN1 : PSSLFileTypePEM;

  switch (fileType) {
    case PSSLFileTypeASN1 :
      if (i2d_X509_bio(out, m_certificate))
        return true;
      break;

    case PSSLFileTypePEM :
      if (PEM_write_bio_X509(out, m_certificate))
        return true;
      break;

    default :
      PAssertAlways(PInvalidParameter);
      return false;
  }

  PTRACE(2, "Error writing certificate file \"" << certFile << '"');
  return false;
}


bool PSSLCertificate::GetSubjectName(X509_Name & name) const
{
  if (m_certificate == NULL)
    return false;

  name = X509_Name(X509_get_subject_name(m_certificate));
  return name.IsValid();
}


PString PSSLCertificate::GetSubjectName() const
{
  X509_Name name;
  return GetSubjectName(name) ? name.AsString() : PString::Empty();
}


bool PSSLCertificate::GetIssuerName(X509_Name & name) const
{
  if (m_certificate == NULL)
    return false;

  name = X509_Name(X509_get_issuer_name(m_certificate));
  return name.IsValid();
}


static PString From_ASN1_STRING(ASN1_STRING * asn)
{
  PString str;
  if (asn != NULL) {
    unsigned char * utf8;
    int len = ASN1_STRING_to_UTF8(&utf8, asn);
    str = PString((const char *)utf8, len);
    OPENSSL_free(utf8);
  }
  return str;
}


PString PSSLCertificate::GetSubjectAltName() const
{
  if (m_certificate == NULL)
    return PString::Empty();

  const GENERAL_NAMES * sANs = (const GENERAL_NAMES *)X509_get_ext_d2i(m_certificate, NID_subject_alt_name, 0, 0);
  if (sANs == NULL)
    return PString::Empty();
 
  int numAN = sk_GENERAL_NAME_num(sANs);
  for (int i = 0; i < numAN; ++i) {
    GENERAL_NAME * sAN = sk_GENERAL_NAME_value(sANs, i);
    // we only care about DNS entries
    if (sAN->type == GEN_DNS)
      return From_ASN1_STRING(sAN->d.dNSName);
  }

  return PString::Empty();
}


bool PSSLCertificate::CheckHostName(const PString & hostname, CheckHostFlags flags)
{
  int sslFlags = 0;
  if (flags&CheckHostAlwaysUseSubject)
    sslFlags |= X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
  if (flags&CheckHostNoWildcards)
    sslFlags |= X509_CHECK_FLAG_NO_WILDCARDS;
  if (flags&CheckHostNoPartialWildcards)
    sslFlags |= X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
  if (flags&CheckHostMultiLabelWildcards)
    sslFlags |= X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS;
  if (flags&CheckHostSingleLabelDomains)
    sslFlags |= X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS;
  return X509_check_host(m_certificate, hostname, hostname.GetLength(), sslFlags, NULL) > 0;
}


PObject::Comparison PSSLCertificate::X509_Name::Compare(const PObject & other) const
{
  int cmp = X509_NAME_cmp(m_name, dynamic_cast<const X509_Name &>(other).m_name);
  if (cmp < 0)
    return LessThan;
  if (cmp > 0)
    return GreaterThan;
  return EqualTo;
}


void PSSLCertificate::X509_Name::PrintOn(ostream & strm) const
{
  strm << AsString();
}


PString PSSLCertificate::X509_Name::GetCommonName() const
{
  return GetNID(NID_commonName);
}


PString PSSLCertificate::X509_Name::GetNID(int id) const
{
  if (m_name != NULL) {
    X509_NAME_ENTRY * entry = X509_NAME_get_entry(m_name, X509_NAME_get_index_by_NID(m_name, id, -1));
    if (entry != NULL)
      return From_ASN1_STRING(X509_NAME_ENTRY_get_data(entry));
  }

  return PString::Empty();
}


PString PSSLCertificate::X509_Name::AsString(int indent) const
{
  PString str;

  if (m_name == NULL)
    return str;

  BIO * bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    return str;

  X509_NAME_print_ex(bio, m_name, std::max(0, indent), indent < 0 ? XN_FLAG_ONELINE : (XN_FLAG_MULTILINE|XN_FLAG_DUMP_UNKNOWN_FIELDS));

  char * data;
  int len = BIO_get_mem_data(bio, &data);
  str = PString(data, len);

  (void)BIO_set_close(bio, BIO_CLOSE);
  BIO_free(bio);
  return str;
}

///////////////////////////////////////////////////////////////////////////////

static char const * const FingerprintHashNames[PSSLCertificateFingerprint::NumHashType] = { "md5", "sha-1", "sha-256", "sha-512" };

PSSLCertificateFingerprint::PSSLCertificateFingerprint()
  : m_hashAlogorithm(NumHashType)
{
}


PSSLCertificateFingerprint::PSSLCertificateFingerprint(const PString & str)
{
  FromString(str);
}


PSSLCertificateFingerprint::PSSLCertificateFingerprint(HashType type, const PSSLCertificate& cert)
  : m_hashAlogorithm(type)
{
  if (m_hashAlogorithm == NumHashType || !cert.IsValid())
    return;

  const EVP_MD* evp = 0;
  switch(m_hashAlogorithm)
  {
    case HashMd5:
      evp = EVP_md5();
      break;
    case HashSha1:
      evp = EVP_sha1();
      break;
    case HashSha256:
      evp = EVP_sha256();
      break;
    case HashSha512:
      evp = EVP_sha512();
      break;
    default:
      break;
  }

  unsigned len = 0;
  unsigned char fp[256];
  if(X509_digest(cert, evp, fp, &len) != 1 || len <= 0) {
    PTRACE(2, "X509_digest() failed: " << PSSLError());
    return;
  }

  for(unsigned i = 0; i < len; ++i)
    m_fingerprint.sprintf(i > 0 ? ":%.2X" : "%.2X", fp[i]);
}


PObject::Comparison PSSLCertificateFingerprint::Compare(const PObject & obj) const
{
  const PSSLCertificateFingerprint & other = dynamic_cast<const PSSLCertificateFingerprint &>(obj);
  if (m_hashAlogorithm < other.m_hashAlogorithm)
    return LessThan;
  if (m_hashAlogorithm > other.m_hashAlogorithm)
    return GreaterThan;
  return m_fingerprint.Compare(other.m_fingerprint);
}


bool PSSLCertificateFingerprint::IsValid() const
{
  return m_hashAlogorithm < NumHashType && !m_fingerprint.IsEmpty();
}


bool PSSLCertificateFingerprint::MatchForCertificate(const PSSLCertificate& cert) const
{
  return (*this == PSSLCertificateFingerprint(m_hashAlogorithm, cert));
}


PString PSSLCertificateFingerprint::AsString() const
{
  if (IsValid())
    return PSTRSTRM(FingerprintHashNames[m_hashAlogorithm] << ' ' << m_fingerprint);

  return PString::Empty();
}


bool PSSLCertificateFingerprint::FromString(const PString & str)
{
  PCaselessString hashType, fp;

  m_fingerprint.MakeEmpty();
  m_hashAlogorithm = NumHashType;

  if (!str.Split(' ', hashType, fp))
    return false;

  for (m_hashAlogorithm = HashMd5; m_hashAlogorithm < EndHashType; ++m_hashAlogorithm) {
    if (hashType == FingerprintHashNames[m_hashAlogorithm]) {
      m_fingerprint = fp.ToUpper();
      return true;
    }
  }

  return false;
}


///////////////////////////////////////////////////////////////////////////////

#ifdef P_SSL_AES
PAESContext::PAESContext()
  : m_key(new AES_KEY)
{
}


PAESContext::PAESContext(bool encrypt, const void * data, PINDEX numBits)
  : m_key(new AES_KEY)
{
  if (encrypt)
    SetEncrypt(data, numBits);
  else
    SetDecrypt(data, numBits);
}


PAESContext::~PAESContext()
{
  delete m_key;
}


void PAESContext::SetEncrypt(const void * data, PINDEX numBits)
{
  AES_set_encrypt_key((const unsigned char *)data, numBits, m_key);
}


void PAESContext::SetDecrypt(const void * data, PINDEX numBits)
{
  AES_set_decrypt_key((const unsigned char *)data, numBits, m_key);
}


void PAESContext::Encrypt(const void * in, void * out)
{
  AES_encrypt((const unsigned char *)in, (unsigned char *)out, m_key);
}


void PAESContext::Decrypt(const void * in, void * out)
{
  AES_decrypt((const unsigned char *)in, (unsigned char *)out, m_key);
}
#endif // P_SSL_AES


///////////////////////////////////////////////////////////////////////////////

PSSLCipherContext::PSSLCipherContext(bool encrypt)
  : m_padMode(PadPKCS)
  , m_encrypt(encrypt)
  , m_context(EVP_CIPHER_CTX_new())
  , m_pad_buf_len(0)
  , m_pad_final_used(false)
{
  memset(m_pad_buf, 0, sizeof(m_pad_buf));
  memset(m_pad_final_buf, 0, sizeof(m_pad_final_buf));

  EVP_CIPHER_CTX_init(m_context);
  EVP_CIPHER_CTX_set_padding(m_context, 1);
}


PSSLCipherContext::~PSSLCipherContext()
{
  EVP_CIPHER_CTX_cleanup(m_context);
  EVP_CIPHER_CTX_free(m_context);
}


PString PSSLCipherContext::GetAlgorithm() const
{
  const EVP_CIPHER * cipher = EVP_CIPHER_CTX_cipher(m_context);
  if (cipher == NULL)
    return PString::Empty();
  return EVP_CIPHER_name(cipher);
}


bool PSSLCipherContext::SetAlgorithm(const PString & name)
{
  const EVP_CIPHER * cipher = EVP_get_cipherbyname(name);
  if (cipher == NULL) {
    cipher = EVP_get_cipherbyobj(OBJ_txt2obj(name, 1));
    if (cipher == NULL) {
      if (name == "1.3.14.3.2.6") // For some reason, not in the OpenSSL database.
        cipher = EVP_des_ecb();
      else {
        PTRACE(2, "Unknown cipher algorithm \"" << name << '"');
        return false;
      }
    }
  }

  if (EVP_CipherInit_ex(m_context, cipher, NULL, NULL, NULL, m_encrypt)) {
    PTRACE(4, "Set cipher algorithm \"" << GetAlgorithm() << "\" from \"" << name << '"');
    return true;
  }

  PTRACE(2, "Could not set cipher algorithm: " << PSSLError());
  return false;
}


bool PSSLCipherContext::SetKey(const BYTE * keyPtr, PINDEX keyLen)
{
  PTRACE(4, "Setting key: " << PHexDump(keyPtr, keyLen));

  if (keyLen < (PINDEX)EVP_CIPHER_CTX_key_length(m_context)) {
    PTRACE(2, "Incorrect key length for encryption");
    return false;
  }

  if (EVP_CipherInit_ex(m_context, NULL, NULL, keyPtr, NULL, m_encrypt))
    return true;

  PTRACE(2, "Could not set key: " << PSSLError());
  return false;
}


bool PSSLCipherContext::SetPadding(PadMode pad)
{
  m_padMode = pad;
  return EVP_CIPHER_CTX_set_padding(m_context, pad != NoPadding) != 0;
}


bool PSSLCipherContext::SetIV(const BYTE * ivPtr, PINDEX ivLen)
{
  if (ivLen < (PINDEX)EVP_CIPHER_CTX_iv_length(m_context)) {
    PTRACE(2, "Incorrect inital vector length for encryption");
    return false;
  }

  if (EVP_CipherInit_ex(m_context, NULL, NULL, NULL, ivPtr, m_encrypt))
    return true;

  PTRACE(2, "Could not set initial vector: " << PSSLError());
  return false;
}


bool PSSLCipherContext::Process(const PBYTEArray & in, PBYTEArray & out)
{
  if (!out.SetMinSize(GetBlockedDataSize(in.GetSize())))
    return false;

  PINDEX outLen = out.GetSize();
  if (!Process(in, in.GetSize(), out.GetPointer(), outLen))
    return false;

  return out.SetSize(outLen);
}

bool PSSLCipherContext::UpdateCTS(unsigned char *out, int *outl, const unsigned char *in, int inl)
{
  const int bl = EVP_CIPHER_CTX_block_size(m_context);
  PAssert(bl <= (int)sizeof(m_pad_buf), PLogicError);
  *outl = 0;

  if (inl <= 0)
    return inl == 0;

  if ((m_pad_buf_len + inl) <= bl) {
    /* new plaintext is no more than 1 block */
    /* copy the in data into the buffer and return */
    memcpy(&(m_pad_buf[m_pad_buf_len]), in, inl);
    m_pad_buf_len += inl;
    return true;
  }

  /* more than 1 block of new plaintext available */
  /* encrypt the previous plaintext, if any */
  if (m_pad_final_used) {
    if (!EVP_Cipher(m_context, out, m_pad_final_buf, bl))
      return false;

    out += bl;
    *outl += bl;
    m_pad_final_used = false;
  }

  /* we already know buf_len + inl must be > bl */
  memcpy(&(m_pad_buf[m_pad_buf_len]), in, (bl - m_pad_buf_len));
  in += (bl - m_pad_buf_len);
  inl -= (bl - m_pad_buf_len);
  m_pad_buf_len = bl;

  if (inl <= bl) {
    memcpy(m_pad_final_buf, m_pad_buf, bl);
    m_pad_final_used = true;
    memcpy(m_pad_buf, in, inl);
    m_pad_buf_len = inl;
    return true;
  }

  if (!EVP_Cipher(m_context, out, m_pad_buf, bl))
    return false;

  out += bl;
  *outl += bl;
  m_pad_buf_len = 0;

  int leftover = inl & (bl - 1);
  if (leftover) {
    inl -= (bl + leftover);
    memcpy(m_pad_buf, &(in[(inl + bl)]), leftover);
    m_pad_buf_len = leftover;
  }
  else {
    inl -= (2 * bl);
    memcpy(m_pad_buf, &(in[(inl + bl)]), bl);
    m_pad_buf_len = bl;
  }
  memcpy(m_pad_final_buf, &(in[inl]), bl);
  m_pad_final_used = true;

  if (!EVP_Cipher(m_context, out, in, inl))
    return false;

  out += inl;
  *outl += inl;

  return true;
}

bool PSSLCipherContext::EncryptFinalCTS(unsigned char *out, int *outl)
{
  unsigned char tmp[EVP_MAX_BLOCK_LENGTH];
  const int bl = EVP_CIPHER_CTX_block_size(m_context);
  int leftover = 0;
  *outl = 0;

  if (!m_pad_final_used) {
    PTRACE(1, "CTS Error: expecting previous ciphertext");
    return false;
  }

  if (m_pad_buf_len == 0) {
    PTRACE(1, "CTS Error: expecting previous plaintext");
    return false;
  }

  /* handle leftover bytes */
  leftover = m_pad_buf_len;

  switch (EVP_CIPHER_CTX_mode(m_context)) {
    case EVP_CIPH_ECB_MODE:
      /* encrypt => C_{n} plus C' */
      if (!EVP_Cipher(m_context, tmp, m_pad_final_buf, bl))
        return false;

      /* P_n plus C' */
      memcpy(&(m_pad_buf[leftover]), &(tmp[leftover]), (bl - leftover));
      /* encrypt => C_{n-1} */
      if (!EVP_Cipher(m_context, out, m_pad_buf, bl))
        return false;

      memcpy((out + bl), tmp, leftover);
      *outl += (bl + leftover);
      return true;

    case EVP_CIPH_CBC_MODE:
      /* encrypt => C_{n} plus C' */
      if (!EVP_Cipher(m_context, tmp, m_pad_final_buf, bl))
        return false;

      /* P_n plus 0s */
      memset(&(m_pad_buf[leftover]), 0, (bl - leftover));

      /* note that in cbc encryption, plaintext will be xor'ed with the previous
              * ciphertext, which is what we want.
              */
      /* encrypt => C_{n-1} */
      if (!EVP_Cipher(m_context, out, m_pad_buf, bl))
        return false;

      memcpy((out + bl), tmp, leftover);
      *outl += (bl + leftover);
      return true;

    default:
      PTRACE(1, "CTS Error: unsupported mode");
      return false;
  }
}

bool PSSLCipherContext::DecryptFinalCTS(unsigned char *out, int *outl)
{
  unsigned char tmp[EVP_MAX_BLOCK_LENGTH];
  const int bl = EVP_CIPHER_CTX_block_size(m_context);
  int leftover = 0;
  *outl = 0;

  if (!m_pad_final_used) {
    PTRACE(1, "CTS Error: expecting previous ciphertext");
    return false;
  }

  if (m_pad_buf_len == 0) {
    PTRACE(1, "CTS Error: expecting previous ciphertext");
    return false;
  }

  /* handle leftover bytes */
  leftover = m_pad_buf_len;

  switch (EVP_CIPHER_CTX_mode(m_context)) {
    case EVP_CIPH_ECB_MODE:
      /* decrypt => P_n plus C' */
      if (!EVP_Cipher(m_context, tmp, m_pad_final_buf, bl))
        return false;

      /* C_n plus C' */
      memcpy(&(m_pad_buf[leftover]), &(tmp[leftover]), (bl - leftover));
      /* decrypt => P_{n-1} */
      if (!EVP_Cipher(m_context, out, m_pad_buf, bl))
        return false;

      memcpy((out + bl), tmp, leftover);
      *outl += (bl + leftover);
      return true;

    case EVP_CIPH_CBC_MODE:
      unsigned char C_n_minus_2[EVP_MAX_BLOCK_LENGTH];

      memcpy(C_n_minus_2, EVP_CIPHER_CTX_iv(m_context), bl);

      /* C_n plus 0s in buf */
      memset(&(m_pad_buf[leftover]), 0, (bl - leftover));

      /* final_buf is C_{n-1} */
      /* decrypt => (P_n plus C')'' */
      if (!EVP_Cipher(m_context, tmp, m_pad_final_buf, bl))
        return false;

      /* XOR'ed with C_{n-2} => (P_n plus C')' */
      for (int i = 0; i < bl; i++)
        tmp[i] = tmp[i] ^ C_n_minus_2[i];

      /* XOR'ed with (C_n plus 0s) => P_n plus C' */
      for (int i = 0; i < bl; i++)
        tmp[i] = tmp[i] ^ m_pad_buf[i];

      /* C_n plus C' in buf */
      memcpy(&(m_pad_buf[leftover]), &(tmp[leftover]), (bl - leftover));
      /* decrypt => P_{n-1}'' */
      if (!EVP_Cipher(m_context, out, m_pad_buf, bl))
        return false;

      /* XOR'ed with C_{n-1} => P_{n-1}' */
      for (int i = 0; i < bl; i++)
        out[i] = out[i] ^ m_pad_final_buf[i];

      /* XOR'ed with C_{n-2} => P_{n-1} */
      for (int i = 0; i < bl; i++)
        out[i] = out[i] ^ C_n_minus_2[i];

      memcpy((out + bl), tmp, leftover);
      *outl += (bl + leftover);
      return true;

    default:
      PTRACE(1, "CTS Error: unsupported mode");
      return false;
  }
}

bool PSSLCipherContext::UpdateLoose(unsigned char *out, int *outl, const unsigned char *in, int inl)
{
  *outl = 0;

  if (inl <= 0)
    return inl == 0;

  const int bl = EVP_CIPHER_CTX_block_size(m_context);
  PAssert(bl <= (int)sizeof(m_pad_buf), PLogicError);
  if (m_pad_buf_len == 0 && (inl & (bl - 1)) == 0) {
    if (!EVP_Cipher(m_context, out, in, inl))
      return false;

    *outl = inl;
    return true;
  }

  int i = m_pad_buf_len;
  if (i != 0) {
    if (i + inl < bl) {
      memcpy(m_pad_buf + i, in, inl);
      m_pad_buf_len += inl;
      return true;
    }

    int j = bl - i;
    memcpy(m_pad_buf + i, in, j);
    if (!EVP_Cipher(m_context, out, m_pad_buf, bl))
      return false;

    inl -= j;
    in += j;
    out += bl;
    *outl = bl;
  }

  i = inl & (bl - 1);
  inl -= i;
  if (inl > 0) {
    if (!EVP_Cipher(m_context, out, in, inl))
      return false;

    *outl += inl;
  }

  if (i != 0)
    memcpy(m_pad_buf, in + inl, i);
  m_pad_buf_len = i;
  return true;
}

bool PSSLCipherContext::DecryptUpdateLoose(unsigned char *out, int *outl, const unsigned char *in, int inl)
{
  if (inl <= 0) {
    *outl = 0;
    return inl == 0;
  }

  const int bl = EVP_CIPHER_CTX_block_size(m_context);
  PAssert(bl <= (int)sizeof(m_pad_final_buf), PLogicError);

  int fix_len = 0;
  if (m_pad_final_used) {
    memcpy(out, m_pad_final_buf, bl);
    out += bl;
    fix_len = 1;
  }

  if (!UpdateLoose(out, outl, in, inl))
    return false;

  /*
     * if we have 'decrypted' a multiple of block size, make sure we have a
     * copy of this last block
     */
  if (bl > 1 && !m_pad_buf_len) {
    *outl -= bl;
    m_pad_final_used = true;
    memcpy(m_pad_final_buf, out + *outl, bl);
  }
  else
    m_pad_final_used = false;

  if (fix_len)
    *outl += bl;

  return true;
}

bool PSSLCipherContext::DecryptFinalLoose(unsigned char *out, int *outl)
{
  *outl = 0;

  const int bl = EVP_CIPHER_CTX_block_size(m_context);
  if (bl > 1) {
    if (m_pad_buf_len || !m_pad_final_used) {
      PTRACE(1, "Decrypt error: wrong final block length");
      return false;
    }

    PAssert(bl <= (int)sizeof(m_pad_final_buf), PLogicError);
    int n = m_pad_final_buf[bl - 1];
    if (n == 0 || n > bl) {
      PTRACE(1, "Decrypt error: bad decrypt");
      return false;
    }

    // Polycom endpoints (eg. m100 and PVX) don't fill the padding propperly, so we have to disable this check
    /*
        for (int i=0; i<n; i++) {
            if (final_buf[bl - i] != n) {
                PTRACE(1, "Decrypt error: incorrect padding");
                return false;
            }
        }
*/
    n = bl - n;
    memcpy(out, m_pad_final_buf, n);
    *outl = n;
  }

  return true;
}

bool PSSLCipherContext::Process(const BYTE * inPtr, PINDEX inLen, BYTE * outPtr, PINDEX & outLen, bool partial)
{
  if (outLen < (m_encrypt ? GetBlockedDataSize(inLen) : inLen))
    return false;

  int len = -1;
  switch (m_padMode) {
    case PadCipherStealing :
      if (!UpdateCTS(outPtr, &len, inPtr, inLen))
        return false;
      break;

    case PadLoosePKCS :
      if (!m_encrypt) {
        if (!DecryptUpdateLoose(outPtr, &len, inPtr, inLen))
          return false;
        break;
      }
      // Do next case

    default :
      if (!EVP_CipherUpdate(m_context, outPtr, &len, inPtr, inLen)) {
        PTRACE(2, "Could not update data: " << PSSLError());
        return false;
      }
  }

  outLen = len;

  if (partial)
    return true;

  switch (m_padMode) {
    case NoPadding :
      if (inLen != outLen) {
        PTRACE(2, "No padding selected and data required padding");
        return false;
      }
      len = 0;
      break;

    // Polycom endpoints (eg. m100 and PVX) don't fill the pading properly, so we have to disable some checks
    case PadLoosePKCS :
      if (!m_encrypt) {
        if (!DecryptFinalLoose(outPtr+len, &len))
          return false;
        break;
      }
      // Do next case

    case PadPKCS :
      if (!EVP_CipherFinal(m_context, outPtr+len, &len)) {
        PTRACE(2, "Could not finalise data: " << PSSLError());
        return false;
      }
      break;

    case PadCipherStealing :
      if (!(m_encrypt ? EncryptFinalCTS(outPtr+len, &len) : DecryptFinalCTS(outPtr+len, &len)))
        return false;
      break;
  }

  outLen += len;
  return true;
}


bool PSSLCipherContext::IsEncrypt() const
{
  return m_encrypt;
}


PINDEX PSSLCipherContext::GetKeyLength() const
{
  return EVP_CIPHER_CTX_key_length(m_context);
}


PINDEX PSSLCipherContext::GetIVLength() const
{
  return EVP_CIPHER_CTX_iv_length(m_context);
}


PINDEX PSSLCipherContext::GetBlockSize() const
{
  return EVP_CIPHER_CTX_block_size(m_context);
}


PINDEX PSSLCipherContext::GetBlockedDataSize(PINDEX size) const
{
  PINDEX blockSize = EVP_CIPHER_CTX_block_size(m_context);
  return ((size+blockSize-1)/blockSize)*blockSize;
}


///////////////////////////////////////////////////////////////////////////////

PSHA1Context::PSHA1Context()
  : m_context(new SHA_CTX)
{
  SHA1_Init(m_context);
}


PSHA1Context::~PSHA1Context()
{
  delete m_context;
}


void PSHA1Context::Update(const void * data, PINDEX length)
{
  SHA1_Update(m_context, data, length);
}


void PSHA1Context::Finalise(BYTE * result)
{
  SHA1_Final(result, m_context);
}


void PSHA1Context::Process(const void * data, PINDEX length, Digest result)
{
  SHA1((const unsigned char *)data, length, result);
}


///////////////////////////////////////////////////////////////////////////////

PSSLDiffieHellman::PSSLDiffieHellman()
  : m_dh(NULL)
{
}


PSSLDiffieHellman::PSSLDiffieHellman(const PFilePath & dhFile, PSSLFileTypes fileType)
  : m_dh(NULL)
{
  Load(dhFile, fileType);
}


PSSLDiffieHellman::PSSLDiffieHellman(PINDEX numBits, const BYTE * pData, const BYTE * gData, const BYTE * pubKey)
  : m_dh(DH_new())
{
  if (PAssertNULL(m_dh) == NULL)
    return;

  PINDEX numBytes = numBits/8;
  if (Construct(pData, numBytes, gData, numBytes, pubKey, numBytes))
    return;

  DH_free(m_dh);
  m_dh = NULL;
}


PSSLDiffieHellman::PSSLDiffieHellman(const PBYTEArray & pData,
                                     const PBYTEArray & gData,
                                     const PBYTEArray & pubKey)
  : m_dh(DH_new())
{
  if (PAssertNULL(m_dh) == NULL)
    return;

  if (Construct(pData, pData.GetSize(), gData, gData.GetSize(), pubKey, pubKey.GetSize()))
    return;

  DH_free(m_dh);
  m_dh = NULL;
}


bool PSSLDiffieHellman::Construct(const BYTE * pData, PINDEX pSize,
                                  const BYTE * gData, PINDEX gSize,
                                  const BYTE * kData, PINDEX kSize)
{
  if (!PAssert(pSize >= 64 && pSize%4 == 0 && gSize <= pSize && kSize <= pSize, PInvalidParameter))
    return false;

  DH_set0_pqg(m_dh, BN_bin2bn(pData, pSize, NULL), NULL, BN_bin2bn(gData, gSize, NULL));

  
#if PTRACING
  int err = -1;
  if (DH_check(m_dh, &err) == 0 || err == -1)
    PTRACE(2, "Unable to check DH values");
  else if (err != 0) {
    PTRACE_IF(2, err&DH_CHECK_P_NOT_PRIME,         "The p value is not prime");
    PTRACE_IF(2, err&DH_CHECK_P_NOT_SAFE_PRIME,    "The p value is not a safe prime");
    PTRACE_IF(2, err&DH_UNABLE_TO_CHECK_GENERATOR, "Unable to check the generator value");
    PTRACE_IF(3, err&DH_NOT_SUITABLE_GENERATOR,    "The g value is not a suitable generator");
    PTRACE_IF(2, err&DH_CHECK_Q_NOT_PRIME,         "The q value is not prime");
    PTRACE_IF(2, err&DH_CHECK_INVALID_Q_VALUE,     "Invalid q value");
    PTRACE_IF(2, err&DH_CHECK_INVALID_J_VALUE,     "Invalid j value");
  }
#endif // PTRACING

  if (kData == NULL) {
    if (DH_generate_key(m_dh))
      return true;

    PSSLAssert("DH key generate failed: ");
    return false;
  }

  if (!PAssert(kSize <= pSize && kSize%4 == 0, PInvalidParameter))
    return false;

  BIGNUM * pub_key = BN_bin2bn(kData, kSize, NULL);
  if (pub_key == NULL) {
    PSSLAssert("DH public key invalid: ");
    return false;
  }

  DH_set0_key(m_dh, pub_key, NULL);
  return true;

}


PSSLDiffieHellman::PSSLDiffieHellman(const PSSLDiffieHellman & diffie)
{
  m_dh = diffie.m_dh;
}


PSSLDiffieHellman & PSSLDiffieHellman::operator=(const PSSLDiffieHellman & diffie)
{
  if (m_dh != NULL)
    DH_free(m_dh);
  m_dh = diffie.m_dh;
  return *this;
}


PSSLDiffieHellman::~PSSLDiffieHellman()
{
    if (m_dh != NULL) {
        DH_free(m_dh);
    }
}

#ifdef P_d2i_DHparams_bio_OLD
// 2/21/04 Yuri Kiryanov - fix for compiler choke on BeOS for usage of
// SSL function d2i_DHparams_bio below in PSSLDiffieHellman::Load
// 5/26/06 Hannes Friederich - Mac OS X seems to need that fix too...
// 3/15/08 Hannes Friederich - Mac OS X 10.5 (Darwin 9.X) no longer needs this
#undef  d2i_DHparams_bio
#define d2i_DHparams_bio(bp,x) \
 (DH *)ASN1_d2i_bio( \
         (char *(*)(...))(void *)DH_new, \
         (char *(*)(...))(void *)d2i_DHparams, \
         (bp), \
         (unsigned char **)(x) \
)
#endif

PBoolean PSSLDiffieHellman::Load(const PFilePath & dhFile, PSSLFileTypes fileType)
{
  if (m_dh != NULL) {
    DH_free(m_dh);
    m_dh = NULL;
  }

  PSSL_BIO in;
  if (!in.OpenRead(dhFile)) {
    PTRACE(2, "Could not open DH file \"" << dhFile << '"');
    return false;
  }

  switch (fileType) {
    case PSSLFileTypeASN1 :
      m_dh = d2i_DHparams_bio(in, NULL);
      if (m_dh != NULL)
        break;

      PTRACE(2, "Invalid ASN.1 DH file \"" << dhFile << '"');
      return false;

    case PSSLFileTypePEM :
      m_dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
      if (m_dh != NULL)
        break;

      PTRACE(2, "Invalid PEM DH file \"" << dhFile << '"');
      return false;

    default :
      m_dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);
      if (m_dh != NULL)
        break;

      m_dh = d2i_DHparams_bio(in, NULL);
      if (m_dh != NULL)
        break;

      PTRACE(2, "Invalid DH file \"" << dhFile << '"');
      return false;
  }

  PTRACE(4, "Loaded DH file \"" << dhFile << '"');
  return false;
}


PINDEX PSSLDiffieHellman::GetNumBits() const
{
  if (m_dh == NULL)
    return 0;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
  return BN_num_bits(m_dh->p);
#else
  return DH_size(m_dh)*8;
#endif
}


static PBYTEArray GetBigNum(const BIGNUM * bn, PINDEX size)
{
  PBYTEArray bytes;

  if (bn == NULL || size == 0)
    return bytes;

  PINDEX numBytes = BN_num_bytes(bn);
  if (size < numBytes)
    size = numBytes;
  if (BN_bn2bin(bn, bytes.GetPointer(size) + size - numBytes) > 0)
    return bytes;

  bytes.SetSize(0);
  return bytes;
}


PBYTEArray PSSLDiffieHellman::GetModulus() const
{
  if (m_dh == NULL)
    return PBYTEArray();

  const BIGNUM * p;
  DH_get0_pqg(m_dh, &p, NULL, NULL);
  return GetBigNum(p, DH_size(m_dh));
}


PBYTEArray PSSLDiffieHellman::GetGenerator() const
{
  if (m_dh == NULL)
    return PBYTEArray();

  const BIGNUM * g;
  DH_get0_pqg(m_dh, NULL, NULL, &g);
  return GetBigNum(g, DH_size(m_dh));
}


PBYTEArray PSSLDiffieHellman::GetHalfKey() const
{
  if (m_dh == NULL)
    return PBYTEArray();

  const BIGNUM * k;
  DH_get0_key(m_dh, &k, NULL);
  return GetBigNum(k, DH_size(m_dh));
}


bool PSSLDiffieHellman::ComputeSessionKey(const PBYTEArray & otherHalf)
{
  if (m_dh == NULL)
    return false;

  BIGNUM * obn = BN_bin2bn(otherHalf, otherHalf.GetSize(), NULL);
  int result = DH_compute_key(m_sessionKey.GetPointer(DH_size(m_dh)), obn, m_dh);
  if (result > 0)
    m_sessionKey.SetSize(result);
  else {
    PTRACE(2, "Could not calculate session key: " << PSSLError());
    m_sessionKey.SetSize(0);
  }
  BN_free(obn);

  return !m_sessionKey.IsEmpty();
}


///////////////////////////////////////////////////////////////////////////////

void PSSLInitialiser::OnStartup()
{
  SSL_library_init();
  SSL_load_error_strings();

  // Seed the random number generator
  BYTE seed[128];
  for (size_t i = 0; i < sizeof(seed); i++)
    seed[i] = (BYTE)rand();
  RAND_seed(seed, sizeof(seed));

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
  // set up multithread stuff
  for (int i = 0; i < CRYPTO_num_locks(); ++i)
    mutexes.push_back(PMutex(PDebugLocation(__FILE__, __LINE__, "SSLMutex")));
  CRYPTO_set_locking_callback(StaticLockingCallback);
  CRYPTO_set_id_callback(ThreadIdCallback);
#endif
}


void PSSLInitialiser::OnShutdown()
{
  CRYPTO_set_locking_callback(NULL);
  ERR_free_strings();
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
  mutexes.clear();
#endif
}


static void InfoCallback(const SSL * PTRACE_PARAM(ssl), int PTRACE_PARAM(location), int PTRACE_PARAM(ret))
{
#if PTRACING
  static const unsigned Level = 4;
  if (PTrace::GetLevel() >= Level) {
    ostream & trace = PTRACE_BEGIN(Level);

    if (location & SSL_CB_ALERT) {
      trace << "Alert "
            << ((location & SSL_CB_READ) ? "read" : "write")
            << ' ' << SSL_alert_type_string_long(ret)
            << ": " << SSL_alert_desc_string_long(ret);
    }
    else {
      if (location & SSL_ST_CONNECT)
        trace << "Connect";
      else if (location & SSL_ST_ACCEPT)
        trace << "Accept";
      else
        trace << "General";

      trace << ": ";

      if (location & SSL_CB_EXIT) {
        if (ret == 0)
          trace << "failed in ";
        else if (ret < 0)
          trace << "error in ";
      }

      trace << "state=" << SSL_state_string_long(ssl);
    }
    trace << PTrace::End;
  }
#endif // PTRACING
}


#if PTRACING
static void TraceVerifyCallback(int ok, X509_STORE_CTX * ctx)
{
  const unsigned Level = ok ? 5 : 2;
  if (PTrace::CanTrace(Level)) {
    ostream & trace = PTRACE_BEGIN(Level);
    trace << "Verify callback: depth=" << X509_STORE_CTX_get_error_depth(ctx);

    int err = X509_STORE_CTX_get_error(ctx);
    if (err != 0)
      trace << ", err=" << err << " - " << X509_verify_cert_error_string(err);

    PSSLCertificate cert(X509_STORE_CTX_get_current_cert(ctx));

    PSSLCertificate::X509_Name x509;
    bool good = cert.GetSubjectName(x509);
    trace << "\n  Subject:";
    if (good)
      trace << '\n' << x509.AsString(4);
    else
      trace << " Invalid!";

    good = cert.GetIssuerName(x509);
    trace << "\n  Issuer:";
    if (good)
      trace << '\n' << x509.AsString(4);
    else
      trace << " Invalid!";

    PString alt = cert.GetSubjectAltName();
    if (!alt.IsEmpty())
      trace << "\n  Subject-Alt: \"" << alt << '"';

    trace << PTrace::End;
  }
}
#else
  #define TraceVerifyCallback(ok, ctx)
#endif // PTRACING

static int VerifyCallback(int ok, X509_STORE_CTX * ctx)
{
  PSSLChannel::VerifyInfo info(ok, X509_STORE_CTX_get_current_cert(ctx), X509_STORE_CTX_get_error(ctx));

  PSSLChannel * channel;
#if (OPENSSL_VERSION_NUMBER < 0x10101000L)
  SSL * ssl = reinterpret_cast<SSL *>(X509_STORE_CTX_get_app_data(ctx));
#else
  SSL * ssl = reinterpret_cast<SSL *>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
#endif
  if (ssl != NULL && (channel = reinterpret_cast<PSSLChannel *>(SSL_get_app_data(ssl))) != NULL)
    channel->OnVerify(info);

  TraceVerifyCallback(ok, ctx);
  return info.m_ok;
}


///////////////////////////////////////////////////////////////////////////////

PSSLContext::PSSLContext(Method method, const void * sessionId, PINDEX idSize)
  : m_method(method)
{
  Construct(sessionId, idSize);
}


PSSLContext::PSSLContext(const void * sessionId, PINDEX idSize)
  : m_method(HighestTLS)
{
  Construct(sessionId, idSize);
}

void PSSLContext::Construct(const void * sessionId, PINDEX idSize)
{
  // create the new SSL context
  const SSL_METHOD * meth;

  switch (m_method) {
    case SSLv3:
#ifndef OPENSSL_NO_SSL3
      // fall through to SSLv23_method if unsupported
      meth = SSLv3_method();
      break;
#endif
    case SSLv23:
      meth = SSLv23_method();
      break;

#if OPENSSL_VERSION_NUMBER > 0x0090819fL
    case TLSv1_1 :
      meth = TLSv1_1_method(); 
      break;
    case TLSv1_2 :
      meth = TLSv1_2_method(); 
      break;
#else
  #pragma message ("Using " OPENSSL_VERSION_TEXT " - TLS 1.1 & 1.2 not available, using 1.0")
    case TLSv1_1 :
    case TLSv1_2 :
#endif
    case TLSv1:
      meth = TLSv1_method(); 
      break;

#if OPENSSL_VERSION_NUMBER > 0x10002000L
    case DTLSv1_2 :
      meth = DTLSv1_2_method(); 
      break;
    case DTLSv1_2_v1_0 :
      meth = DTLS_method(); 
      break;
#else
  #pragma message ("Using " OPENSSL_VERSION_TEXT " - DTLS 1.2 not available, using 1.0")
    case DTLSv1_2 :
    case DTLSv1_2_v1_0 :
#endif
    case DTLSv1:
      meth = DTLSv1_method();
      break;
    default :
      PAssertAlways("Unsupported TLS/DTLS version");
      m_context = NULL;
      return;
  }

  m_context = SSL_CTX_new(meth);
  if (m_context == NULL) {
    PSSLAssert("Error creating context: ");
    return;
  }

  if (sessionId != NULL) {
    if (idSize == 0)
      idSize = ::strlen((const char *)sessionId)+1;
    SSL_CTX_set_session_id_context(m_context, (const BYTE *)sessionId, idSize);
    SSL_CTX_sess_set_cache_size(m_context, 128);
  }

  SSL_CTX_set_info_callback(m_context, InfoCallback);
  SetVerifyMode(VerifyNone);

  /* Specify an ECDH group for ECDHE ciphers, otherwise they cannot be
     negotiated when acting as the server. Use NIST's P-256 which is commonly
     supported. */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  SSL_CTX_set_ecdh_auto(m_context, 1);
#else
  EC_KEY* ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (ecdh != NULL) {
    SSL_CTX_set_options(m_context, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_tmp_ecdh(m_context, ecdh);
    EC_KEY_free(ecdh);
  }
#endif

  PTRACE(4, "Constructed context: method=" << m_method << " ctx=" << m_context);
}


PSSLContext::~PSSLContext()
{
  PTRACE(4, "Destroyed context: method=" << m_method << " ctx=" << m_context);
  if (m_context != NULL)
    SSL_CTX_free(m_context);
}


bool PSSLContext::SetVerifyLocations(const PFilePath & caFile, const PDirectory & caDir)
{
  if (PAssertNULL(m_context) == NULL)
    return false;

  if (caFile.IsEmpty())
    return SetVerifyDirectory(caDir); // Directory can never be empty.

  if (SSL_CTX_load_verify_locations(m_context, caFile, caDir)) {
    PTRACE(4, "Set context " << m_context << " verify locations file=\"" << caFile << "\", dir=\"" << caDir << '"');
    return true;
  }

  PTRACE(2, "Could not set context " << m_context << " verify locations file=\"" << caFile << "\", dir=\"" << caDir << '"');
  return SSL_CTX_set_default_verify_paths(m_context);
}


bool PSSLContext::SetVerifyDirectory(const PDirectory & caDir)
{
  if (SSL_CTX_load_verify_locations(m_context, NULL, caDir)) {
    PTRACE(4, "Set context " << m_context << " verify directory \"" << caDir << '"');
    return true;
  }

  PTRACE(2, "Could not set context " << m_context << " verify directory \"" << caDir << '"');
  return SSL_CTX_set_default_verify_paths(m_context);
}


bool PSSLContext::SetVerifyFile(const PFilePath & caFile)
{
  if (SSL_CTX_load_verify_locations(m_context, caFile, NULL)) {
    PTRACE(4, "Set context " << m_context << " verify file \"" << caFile << '"');
    return true;
  }

  PTRACE(2, "Could not set context " << m_context << " verify locations file \"" << caFile << '"');
  return SSL_CTX_set_default_verify_paths(m_context);
}


bool PSSLContext::SetVerifySystemDefault()
{
#if _WIN32
    HCERTSTORE hStore = CertOpenSystemStore(NULL, "ROOT");
    if (hStore != NULL) {
      X509_STORE *store = X509_STORE_new();
      unsigned count = 0;

      PCCERT_CONTEXT pContext = NULL;
      while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
        X509 *x509 = d2i_X509(NULL, (const unsigned char **)&pContext->pbCertEncoded, pContext->cbCertEncoded);
        if (x509 == NULL)
          PTRACE(2, "Could not create OpenSSL X.509 certificate from Windows Certificate Store: " << PSSLError());
        else {
          if (X509_STORE_add_cert(store, x509))
            ++count;
          else
            PTRACE_IF(2, ERR_peek_error() != 0x0B07C065, "Could not add certificate OpenSSL X.509 store: " << PSSLError());
          X509_free(x509);
        }
      }

      CertFreeCertificateContext(pContext);
      CertCloseStore(hStore, 0);

      if (count > 0) {
        SSL_CTX_set_cert_store(m_context, store);
        PTRACE(4, "Set context " << m_context << " to use " << count << " certificates from Windows Certificate Store");
        return true;
      }

      PTRACE(2, "No usable certificates in Windows System Certificate store for context " << m_context);
    }
    else
      PTRACE(2, "Could not open Windows System Certificate store for context " << m_context);
#else
    static const char * const caBundles[] = {
      "/etc/pki/tls/certs/ca-bundle.crt",
      "/etc/ssl/certs/ca-bundle.crt"
    };
    for (PINDEX i = 0; i < PARRAYSIZE(caBundles); ++i) {
      if (SSL_CTX_load_verify_locations(m_context, caBundles[i], NULL)) {
        PTRACE(4, "Set context " << m_context << " to system certificates store at " << caBundles[i]);
        return true;
      }
    }

    PTRACE(2, "Could not set context " << m_context << " to system certficate store.");
#endif // _WIN32

  return SSL_CTX_set_default_verify_paths(m_context);
}


bool PSSLContext::SetVerifyCertificate(const PSSLCertificate & cert)
{
  if (PAssertNULL(m_context) == NULL || !cert.IsValid())
    return false;

  X509_STORE * store = SSL_CTX_get_cert_store(m_context);
  if (store == NULL)
    return false;

  return X509_STORE_add_cert(store, cert);
}


static int VerifyModeBits[PSSLContext::EndVerifyMode] = {
  SSL_VERIFY_NONE,
  SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
  SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
};


void PSSLContext::SetVerifyMode(VerifyMode mode, unsigned depth)
{
  if (PAssertNULL(m_context) == NULL)
    return;

  SSL_CTX_set_verify(m_context, VerifyModeBits[mode], VerifyCallback);
  SSL_CTX_set_verify_depth(m_context, depth);
}


PSSLContext::VerifyMode PSSLContext::GetVerifyMode() const
{
  if (PAssertNULL(m_context) == NULL)
    return VerifyNone;

  int v = SSL_CTX_get_verify_mode(m_context);
  if (v == SSL_VERIFY_NONE)
    return VerifyNone;
  if ((v&SSL_VERIFY_FAIL_IF_NO_PEER_CERT) == 0)
    return VerifyPeer;
  return VerifyPeerMandatory;
}


bool PSSLContext::AddClientCA(const PSSLCertificate & certificate)
{
  return PAssertNULL(m_context) != NULL &&
         certificate.IsValid() &&
         SSL_CTX_add_client_CA(m_context, certificate);
}


bool PSSLContext::AddClientCA(const PList<PSSLCertificate> & certificates)
{
  if (PAssertNULL(m_context) == NULL)
    return false;

  for (PList<PSSLCertificate>::const_iterator it = certificates.begin(); it != certificates.end(); ++it) {
    if (!it->IsValid() || !SSL_CTX_add_client_CA(m_context, *it))
      return false;
  }

  return true;
}


bool PSSLContext::UseCertificate(const PSSLCertificate & certificate)
{
  if (PAssertNULL(m_context) == NULL)
    return false;

  if (!certificate.IsValid())
    return false;

  if (SSL_CTX_use_certificate(m_context, certificate) == 0) {
    PTRACE(2, "Could not use certificate: " << PSSLError());
    return false;
  }

  const PSSLCertificate::X509_Chain & chain = certificate.GetChain();

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  SSL_CTX_clear_chain_certs(m_context);
#else
  SSL_CTX_clear_extra_chain_certs(m_context);
#endif

  for (PSSLCertificate::X509_Chain::const_iterator it = chain.begin(); it != chain.end(); ++it) {
    X509 * ca = X509_dup(*it);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (!SSL_CTX_add0_chain_cert(m_context, ca)) {
#else
    if (!SSL_CTX_add_extra_chain_cert(m_context, ca)) {
#endif
      PTRACE(2, "Could not use certificate chain: " << PSSLError());
      X509_free(ca);
      return false;
    }
  }

  PTRACE(5, "Using certificate with " << chain.size() << " CAs in chain");
  return true;
}


bool PSSLContext::UsePrivateKey(const PSSLPrivateKey & key)
{
  return PAssertNULL(m_context) != NULL &&
         SSL_CTX_use_PrivateKey(m_context, key) > 0 &&
         SSL_CTX_check_private_key(m_context);
}


bool PSSLContext::UseDiffieHellman(const PSSLDiffieHellman & dh)
{
  return PAssertNULL(m_context) != NULL &&
         dh.IsValid() &&
         SSL_CTX_set_tmp_dh(m_context, (dh_st *)dh) > 0;
}


bool PSSLContext::SetCipherList(const PString & ciphers)
{
  return PAssertNULL(m_context) != NULL &&
         !ciphers.IsEmpty() &&
         SSL_CTX_set_cipher_list(m_context, (char *)(const char *)ciphers);
}


bool PSSLContext::SetCredentials(const PString & authority,
                                 const PString & certificate,
                                 const PString & privateKey,
                                 bool create)
{
  if (PAssertNULL(m_context) == NULL)
    return false;

  if (!authority.IsEmpty()) {
    bool ok;
    if (authority == "*")
      ok = SetVerifySystemDefault();
    else if (PDirectory::Exists(authority))
      ok = SetVerifyDirectory(authority);
    else if (PFile::Exists(authority))
      ok = SetVerifyFile(authority);
    else
      ok = SetVerifyCertificate(PSSLCertificate(authority));
    if (!ok) {
      PTRACE(2, "Could not find/parse certificate authority \"" << authority << '"');
      return false;
    }
    SetVerifyMode(VerifyPeerMandatory);
  }

  if (certificate.IsEmpty() && privateKey.IsEmpty())
    return true;

  PSSLCertificate cert;
  PSSLPrivateKey key;

  if (PFile::Exists(certificate) && !cert.Load(certificate)) {
    PTRACE(2, "Could not load certificate file \"" << certificate << '"');
    return false;
  }

  if (PFile::Exists(privateKey) && !key.Load(privateKey, PSSLFileTypeDEFAULT, m_passwordNotifier)) {
    PTRACE(2, "Could not load private key file \"" << privateKey << '"');
    return false;
  }

  // Can put the base64 directly into string, rather than file path
  if (!key.IsValid())
    key.Parse(privateKey);

  if (!cert.IsValid())
    cert.Parse(certificate);

  if (!cert.IsValid() || !key.IsValid()) {

    if (cert.IsValid() || key.IsValid()) {
      PTRACE(2, "Require both certificate and private key");
      return false;
    }

    if (!create) {
      PTRACE(2, "Require certificate and private key");
      return false;
    }

    PStringStream dn;
    dn << "/O=" << PProcess::Current().GetManufacturer()
       << "/CN=" << PIPSocket::GetHostName();

    if (!key.Create(2048)) {
      PTRACE(1, "Could not create private key");
      return false;
    }

    if (!cert.CreateRoot(dn, key)) {
      PTRACE(1, "Could not create certificate");
      return false;
    }

    if (!cert.Save(certificate))
      return false;

    PTRACE(2, "Created new certificate file \"" << certificate << '"');

    if (!key.Save(privateKey, true))
      return false;

    PTRACE(2, "Created new private key file \"" << privateKey << '"');
  }

  if (!UseCertificate(cert)) {
    PTRACE(1, "Could not use certificate " << cert);
    return false;
  }

  if (!UsePrivateKey(key)) {
    PTRACE(1, "Could not use private key " << key);
    return false;
  }

  return true;
}


void PSSLContext::SetPasswordNotifier(const PSSLPasswordNotifier & notifier)
{
  if (PAssertNULL(m_context) == NULL)
    return;

  m_passwordNotifier = notifier;
  if (notifier.IsNULL())
    SSL_CTX_set_default_passwd_cb(m_context, NULL);
  else {
    SSL_CTX_set_default_passwd_cb(m_context, PasswordCallback);
    SSL_CTX_set_default_passwd_cb_userdata(m_context, &m_passwordNotifier);
  }
}


bool PSSLContext::SetExtension(const char * extension)
{
#if P_SSL_SRTP
  return PAssertNULL(m_context) != NULL &&
         extension != NULL && *extension != '\0' &&
         SSL_CTX_set_tlsext_use_srtp(m_context, extension) == 0;
#else
  return false;
#endif
}


/////////////////////////////////////////////////////////////////////////
//
//  SSLChannel
//

PSSLChannel::PSSLChannel(PSSLContext * ctx, PBoolean autoDel)
{
  if (ctx != NULL)
    Construct(ctx, autoDel);
  else
    Construct(new PSSLContext, true);
}


PSSLChannel::PSSLChannel(PSSLContext & ctx)
{
  Construct(&ctx, false);
}


void PSSLChannel::Construct(PSSLContext * ctx, PBoolean autoDel)
{
  m_context = ctx;
  m_autoDeleteContext = autoDel;

  m_ssl = SSL_new(*m_context);
  if (m_ssl == NULL) {
    PSSLAssert("Error creating channel: ");
    return;
  }

  SSL_set_app_data(m_ssl, this);

  m_bioMethod = BIO_meth_new(BIO_TYPE_SOCKET, "PTLib-PSSLChannel");
  BIO_meth_set_write(m_bioMethod, BioWrite);
  BIO_meth_set_read(m_bioMethod, BioRead);
  BIO_meth_set_ctrl(m_bioMethod, BioControl);
  BIO_meth_set_destroy(m_bioMethod, BioClose);

  m_bio = BIO_new(m_bioMethod);
  if (m_bio == NULL) {
    PSSLAssert("Error creating BIO: ");
    return;
  }

  BIO_set_data(m_bio, this);
  BIO_set_init(m_bio, 1);
  SSL_set_bio(m_ssl, m_bio, m_bio);

  PTRACE(4, "Constructed channel: ssl=" << m_ssl << " method=" << m_context->GetMethod() << " context=" << &*m_context);
}


PSSLChannel::~PSSLChannel()
{
  PTRACE(4, "Destroyed channel: ssl=" << m_ssl << " method=" << m_context->GetMethod() << " context=" << &*m_context);

  // free the SSL connection
  if (m_ssl != NULL)
    SSL_free(m_ssl);

  // The above free of SSL also frees the m_bio, no need to it here
  // But we do need to clean up the bio method

  if (m_bioMethod != NULL)
    BIO_meth_free(m_bioMethod);

  if (m_autoDeleteContext)
    delete m_context;
}


PBoolean PSSLChannel::Read(void * buf, PINDEX len)
{
  if (PAssertNULL(m_ssl) == NULL)
    return false;

  channelPointerMutex.StartRead();

  SetLastReadCount(0);

  PBoolean returnValue = false;
  if (readChannel == NULL)
    SetErrorValues(NotOpen, EBADF, LastReadError);
  else if (readTimeout == 0 && SSL_pending(m_ssl) == 0)
    SetErrorValues(Timeout, ETIMEDOUT, LastReadError);
  else {
    readChannel->SetReadTimeout(readTimeout);

    int readResult = SSL_read(m_ssl, (char *)buf, len);
    SetLastReadCount(readResult);
    returnValue = readResult > 0;
    if (readResult < 0 && GetErrorCode(LastReadError) == NoError)
      ConvertOSError(-1, LastReadError);
  }

  channelPointerMutex.EndRead();

  return returnValue;
}


int PSSLChannel::BioRead(bio_st * bio, char * buf, int len)
{
  if (bio == NULL)
    return -1;

  void * p = BIO_get_data(bio);
  if (p == NULL)
    return -1;

  return reinterpret_cast<PSSLChannel *>(p)->BioRead(buf, len);
}


int PSSLChannel::BioRead(char * buf, int len)
{
  BIO_clear_retry_flags(m_bio);

  // Skip over the polymorphic read, want to do real one
  if (PIndirectChannel::Read(buf, len))
    return GetLastReadCount();

  switch (GetErrorCode(PChannel::LastReadError)) {
    case PChannel::Interrupted :
    case PChannel::Unavailable :
      BIO_set_retry_read(m_bio); // Non fatal, keep trying
    default :
        break;
  }

  return -1;
}


PBoolean PSSLChannel::Write(const void * buf, PINDEX len)
{
  if (PAssertNULL(m_ssl) == NULL)
    return false;

  flush();

  /* OpenSSL claims to be thread safe if we use CRYPTO_set_locking_callback().
     However, evidence is, that simultaneous writes are still ... bad. */
  PWaitAndSignal lock(m_writeMutex);

  channelPointerMutex.StartRead();

  SetLastWriteCount(0);

  PBoolean returnValue;
  if (writeChannel == NULL) {
    SetErrorValues(NotOpen, EBADF, LastWriteError);
    returnValue = false;
  }
  else {
    writeChannel->SetWriteTimeout(writeTimeout);

    int writeResult = SSL_write(m_ssl, (const char *)buf, len);
    returnValue = writeResult >= 0 && SetLastWriteCount(writeResult) >= len;
    if (writeResult < 0 && GetErrorCode(LastWriteError) == NoError)
      ConvertOSError(-1, LastWriteError);
  }

  channelPointerMutex.EndRead();

  return returnValue;
}


int PSSLChannel::BioWrite(bio_st * bio, const char * buf, int len)
{
  if (bio == NULL)
    return -1;

  void * p = BIO_get_data(bio);
  if (p == NULL)
    return -1;

  return reinterpret_cast<PSSLChannel *>(p)->BioWrite(buf, len);
}


int PSSLChannel::BioWrite(const char * buf, int len)
{
  BIO_clear_retry_flags(m_bio);

  // Skip over the polymorphic write, want to do real one
  if (PIndirectChannel::Write(buf, len))
    return GetLastWriteCount();

  switch (GetErrorCode(PChannel::LastWriteError)) {
    case PChannel::Interrupted :
    case PChannel::Unavailable :
      BIO_set_retry_write(m_bio); // Non fatal, keep trying
    default :
        break;
  }

  return -1;
}


PBoolean PSSLChannel::Shutdown(ShutdownValue value)
{
  if (value != ShutdownReadAndWrite)
    return SetErrorValues(BadParameter, EINVAL);

  bool ok = PAssertNULL(m_ssl) != NULL && SSL_shutdown(m_ssl);
  return PIndirectChannel::Shutdown(value) && ok;
}


PBoolean PSSLChannel::Close()
{
  bool ok = Shutdown(ShutdownReadAndWrite);
  return PIndirectChannel::Close() && ok;
}


int PSSLChannel::BioClose(bio_st * bio)
{
  if (bio == NULL)
    return 0;

  void * p = BIO_get_data(bio);
  if (p == NULL)
    return 0;

  return reinterpret_cast<PSSLChannel *>(p)->BioClose();
}


int PSSLChannel::BioClose()
{
  if (BIO_get_shutdown(m_bio)) {
    if (BIO_get_init(m_bio)) {
      Shutdown(PSocket::ShutdownReadAndWrite);
      PIndirectChannel::Close(); // Don't do PSSLChannel::Close() as OpenSSL might die
    }
    BIO_set_init(m_bio, 0);
    BIO_set_flags(m_bio, 0);
  }

  return 1;
}


PBoolean PSSLChannel::ConvertOSError(P_INT_PTR libcReturnValue, ErrorGroup group)
{
  if (m_ssl == NULL)
    return SetErrorValues(NotOpen, EBADF, group);

  if (libcReturnValue >= 0)
    return SetErrorValues(NoError, 0, group);

  Errors lastError = AccessDenied;
  DWORD osError = SSL_get_error(m_ssl, (int)libcReturnValue);
  if (osError == SSL_ERROR_NONE)
    osError = ERR_peek_error();
  osError |= 0x80000000;

  if (osError == 0x94090086) {
    int certVerifyError = GetErrorNumber(LastGeneralError);
    if ((certVerifyError & 0xc0000000) == 0xc0000000)
      osError = certVerifyError;
  }

  return SetErrorValues(lastError, osError, group);
}


PString PSSLChannel::GetErrorText(ErrorGroup group) const
{
  unsigned err = GetErrorNumber(group);
  if ((err&0x80000000) == 0)
    return PIndirectChannel::GetErrorText(group);

  if (err == 0xe0000000)
    return "Certificate subject invalid for host";

  if ((err & 0x40000000) != 0)
    return X509_verify_cert_error_string(err&0x3fffffff);

  return PSSLError(err&0x7fffffff);
}


PBoolean PSSLChannel::Accept()
{
  return IsOpen() && InternalAccept();
}


PBoolean PSSLChannel::Accept(PChannel & channel)
{
  return Open(channel) && InternalAccept();
}


PBoolean PSSLChannel::Accept(PChannel * channel, PBoolean autoDelete)
{
  return Open(channel, autoDelete) && InternalAccept();
}


bool PSSLChannel::InternalAccept()
{
  return PAssertNULL(m_ssl) != NULL && ConvertOSError(SSL_accept(m_ssl));
}


PBoolean PSSLChannel::Connect()
{
  return IsOpen() && InternalConnect();
}


PBoolean PSSLChannel::Connect(PChannel & channel)
{
  return Open(channel) && InternalConnect();
}


PBoolean PSSLChannel::Connect(PChannel * channel, PBoolean autoDelete)
{
  return Open(channel, autoDelete) && InternalConnect();
}


bool PSSLChannel::InternalConnect()
{
  return PAssertNULL(m_ssl) != NULL && ConvertOSError(SSL_connect(m_ssl));
}


PBoolean PSSLChannel::AddClientCA(const PSSLCertificate & certificate)
{
  return PAssertNULL(m_ssl) != NULL && SSL_add_client_CA(m_ssl, certificate);
}


PBoolean PSSLChannel::AddClientCA(const PList<PSSLCertificate> & certificates)
{
  if (PAssertNULL(m_ssl) == NULL)
    return false;

  for (PList<PSSLCertificate>::const_iterator it = certificates.begin(); it != certificates.end(); ++it) {
    if (!SSL_add_client_CA(m_ssl, *it))
      return false;
  }

  return true;
}


PBoolean PSSLChannel::UseCertificate(const PSSLCertificate & certificate)
{
  return PAssertNULL(m_ssl) != NULL && SSL_use_certificate(m_ssl, certificate);
}


PBoolean PSSLChannel::UsePrivateKey(const PSSLPrivateKey & key)
{
  return PAssertNULL(m_ssl) != NULL &&
         SSL_use_PrivateKey(m_ssl, key) > 0 &&
         SSL_check_private_key(m_ssl);
}


PString PSSLChannel::GetCipherList() const
{
  if (PAssertNULL(m_ssl) == NULL)
    return false;

  PStringStream strm;
  int i = -1;
  const char * str;
  while ((str = SSL_get_cipher_list(m_ssl,++i)) != NULL) {
    if (i > 0)
      strm << ':';
    strm << str;
  }

  return strm;
}


void PSSLChannel::SetVerifyMode(VerifyMode mode, const VerifyNotifier & notifier)
{
  m_verifyNotifier = notifier;

  if (PAssertNULL(m_ssl) != NULL)
    SSL_set_verify(m_ssl, VerifyModeBits[mode], VerifyCallback);
}


void PSSLChannel::OnVerify(VerifyInfo & info)
{
  if (!m_verifyNotifier.IsNULL())
    m_verifyNotifier(*this, info);

  if (info.m_errorCode != 0)
    SetErrorValues(AccessDenied, 0xc0000000 | info.m_errorCode, LastGeneralError);
}


bool PSSLChannel::GetPeerCertificate(PSSLCertificate & certificate, PString * error)
{
  if (PAssertNULL(m_ssl) == NULL)
    return false;

  long err = SSL_get_verify_result(m_ssl);
  certificate.Attach(SSL_get_peer_certificate(m_ssl));

  if (err == X509_V_OK && certificate.IsValid())
    return true;

  if (error != NULL) {
    if (err != X509_V_OK)
      *error = X509_verify_cert_error_string(err);
    else
      *error = "Peer did not offer certificate";
  }

  if (err == X509_V_OK && (SSL_get_verify_mode(m_ssl)&SSL_VERIFY_FAIL_IF_NO_PEER_CERT) == 0)
    return true;

  return SetErrorValues(AccessDenied, 0xc0000000 | err, LastGeneralError);
}


long PSSLChannel::BioControl(bio_st * bio, int cmd, long num, void * ptr)
{
  if (bio == NULL)
    return 0;

  void * p = BIO_get_data(bio);
  if (p == NULL)
    return 0;

  return reinterpret_cast<PSSLChannel *>(p)->BioControl(cmd, num, ptr);
}


long PSSLChannel::BioControl(int cmd, long num, void * /*ptr*/)
{
  switch (cmd) {
    case BIO_CTRL_SET_CLOSE:
      BIO_set_shutdown(m_bio, num);
      return 1;

    case BIO_CTRL_GET_CLOSE:
      return BIO_get_shutdown(m_bio);

    case BIO_CTRL_FLUSH:
      return 1;
  }

  // Other BIO commands, return 0
  return 0;
}


bool PSSLChannel::SetServerNameIndication(const PString & name)
{
  return m_ssl != NULL && SSL_set_tlsext_host_name(m_ssl, name.GetPointer());
}


bool PSSLChannel::CheckHostName(const PString & hostname, PSSLCertificate::CheckHostFlags flags)
{
  if (SSL_get_verify_mode(m_ssl) == 0)
    return true;

  PSSLCertificate certificate;
  if (!GetPeerCertificate(certificate))
    return false;

  if (certificate.CheckHostName(hostname, flags))
    return true;

  return SetErrorValues(AccessDenied, 0xe0000000, LastGeneralError);
}


///////////////////////////////////////////////////////////////////////////////

PSSLChannelDTLS::PSSLChannelDTLS(PSSLContext * context, bool autoDeleteContext)
  : PSSLChannel(context, autoDeleteContext)
{
}


PSSLChannelDTLS::PSSLChannelDTLS(PSSLContext & context)
  : PSSLChannel(context)
{
}


PSSLChannelDTLS::~PSSLChannelDTLS()
{
}


bool PSSLChannelDTLS::SetMTU(unsigned mtu)
{
  if (PAssertNULL(m_ssl) == NULL)
    return false;

  static unsigned MinMTU = 576-8-20; // RFC879 indicates this is ALWAYS good
  if (mtu < MinMTU)
    mtu = MinMTU;
  else if (mtu > 65535) // Largest possible UDP packet
    mtu = 65535;

#ifdef SSL_OP_NO_QUERY_MTU
  SSL_set_options(m_ssl, SSL_OP_NO_QUERY_MTU);
#endif
  SSL_set_mtu(m_ssl, mtu);
  return true;
}


PBoolean PSSLChannelDTLS::Read(void * buf, PINDEX len)
{
  /* Unlike PSSLChannel, data not associated with handshake, which will use
     the BioRead() function, just pass through to the real channel. */
  return PIndirectChannel::Read(buf, len);
}


PBoolean PSSLChannelDTLS::Write(const void * buf, PINDEX len)
{
  /* Unlike PSSLChannel, data not associated with handshake, which will use
     the BioWrite() function, just pass through to the real channel. */
  return PIndirectChannel::Write(buf, len);
}


bool PSSLChannelDTLS::ExecuteHandshake()
{
  if (PAssertNULL(m_ssl) == NULL)
    return false;

  SSL_set_mode(m_ssl, SSL_MODE_AUTO_RETRY);
  SSL_set_read_ahead(m_ssl, 1);
  SSL_CTX_set_read_ahead(*m_context, 1);

  for (;;) {
    PTRACE(5, "DTLS executing handshake.");
    int ret = SSL_do_handshake(m_ssl);
    if (ret == 1)
      return SetErrorValues(NoError, 0, LastGeneralError);

    if (CheckNotOpen())
      return false;

    switch (SSL_get_error(m_ssl, ret)) {
      case SSL_ERROR_WANT_READ :
      case SSL_ERROR_WANT_WRITE :
        break; // Do handshake again

      default :
        return ConvertOSError(-1, LastGeneralError);
    }
  }
}


bool PSSLChannelDTLS::IsServer() const
{
  return PAssertNULL(m_ssl) != NULL && SSL_is_server(m_ssl);
}


PCaselessString PSSLChannelDTLS::GetSelectedProfile() const
{
  if (PAssertNULL(m_ssl) == NULL)
    return PString::Empty();

#if P_SSL_SRTP
  SRTP_PROTECTION_PROFILE *p = SSL_get_selected_srtp_profile(m_ssl);
  if (p != NULL)
    return p->name;

  PTRACE(2, "SSL_get_selected_srtp_profile returned NULL: " << PSSLError());
#endif
  return PString::Empty();
}


PBYTEArray PSSLChannelDTLS::GetKeyMaterial(PINDEX materialSize, const char * name) const
{
  if (PAssertNULL(m_ssl) == NULL)
    return PBYTEArray();

#if P_SSL_SRTP
  if (PAssert(materialSize > 0 && name != NULL && *name != '\0', PInvalidParameter)) {
    PBYTEArray result;
    if (SSL_export_keying_material(m_ssl,
                                   result.GetPointer(materialSize), materialSize,
                                   name, strlen(name),
                                   NULL, 0, 0) == 1)
      return result;

    PTRACE(2, "SSL_export_keying_material failed: " << PSSLError());
  }
#endif

  return PBYTEArray();
}


bool PSSLChannelDTLS::InternalAccept()
{
  if (PAssertNULL(m_ssl) == NULL)
    return false;

  SSL_set_accept_state(m_ssl);
  return true;
}


bool PSSLChannelDTLS::InternalConnect()
{
  if (PAssertNULL(m_ssl) == NULL)
    return false;

  SSL_set_connect_state(m_ssl);
  return true;
}
#endif // P_SSL
