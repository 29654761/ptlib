/*
 * cypher.h
 *
 * Encryption support classes.
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
 */


#ifndef PTLIB_CYPHER_H
#define PTLIB_CYPHER_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif

#if P_CYPHER

/** RFC4013 "SASLprep" compatible string.
    For security systems, often some identifiers, usersname, passwords etc
    must not contain extraneous characters. This class represents a string
    that will obey (most) of those rules.
  */
class PSASLString : public PString
{
    PCLASSINFO(PSASLString, PString);
  public:
    PSASLString() { }
    PSASLString(const char * str)    { AppendValidated(str); }
    PSASLString(const PString & str) { AppendValidated(str); }
    PSASLString(const PSASLString & str) : PString(str) { }

    PSASLString & operator=(char ch)                 { MakeEmpty(); AppendValidated(ch);  return *this; }
    PSASLString & operator=(wchar_t ch)              { MakeEmpty(); AppendValidated(ch);  return *this; }
    PSASLString & operator=(const char * str)        { MakeEmpty(); AppendValidated(str); return *this; }
    PSASLString & operator=(const PString & str)     { MakeEmpty(); AppendValidated(str); return *this; }
    PSASLString & operator=(const PSASLString & str) { PString::operator=(str);           return *this; }

    PSASLString & operator+=(char ch)                 { AppendValidated(ch);     return *this; }
    PSASLString & operator+=(wchar_t ch)              { AppendValidated(ch);     return *this; }
    PSASLString & operator+=(const char * str)        { AppendValidated(str);    return *this; }
    PSASLString & operator+=(const PString & str)     { AppendValidated(str);    return *this; }
    PSASLString & operator+=(const PSASLString & str) { PString::operator=(str); return *this; }

  protected:
    void AppendValidated(const char * str);
    void AppendValidated(wchar_t ch);
};


/** This class is used to encode/decode data using the MIME standard base64
   encoding mechanism as defined in RFC1521.

   To encode a large block of data use the following seqeunce:
<pre><code>
      PBase64 base;
      base.StartEncoding();
      while (Read(dataChunk)) {
        base.ProcessEncoding(dataChunk);
        out << base.GetEncodedString();
      }
      out << base.CompleteEncoding();
</code></pre>

    if smaller blocks that fit easily in memory are to be encoded the
    <code>Encode()</code> functions can be used to everything in one go.

    To decode a large block of data use the following sequence:
<pre><code>

      PBase64 base;
      base.StartDecoding();
      while (Read(str) && ProcessDecoding(str))
        Write(base.GetDecodedData());
      Write(base.GetDecodedData());
</code></pre>

    if smaller blocks that fit easily in memory are to be decoded the
    <code>Decode()</code> functions can be used to everything in one go.
 */
class PBase64 : public PObject
{
  PCLASSINFO(PBase64, PObject);

  public:
    /// Encoding options
    enum Options {
      e_CRLF, ///< Line endings are CR LF
      e_LF,   ///< Line endings are LF only
      e_NoLF, ///< No line endings
      e_URL   ///< URL safe encoding, no line breaks, no trailing '= and alternate alphabet
    };

    /** Construct a base 64 encoder/decoder and initialise both encode and
       decode members as in <code>StartEncoding()</code> and <code>StartDecoding()</code>.
     */
    explicit PBase64(
      Options options = e_CRLF,  ///< Options for encoding.
      PINDEX width = 76          ///< Line widths if options != e_URL
    );

    /// Start a base 64 encoding operation, initialising the object instance.
    void StartEncoding(
      Options options = e_CRLF,  ///< Options for encoding.
      PINDEX width = 76          ///< Line widths if options != e_URL
    );
    void StartEncoding(
      const char * endOfLine,  ///< String to use for end of line.
      PINDEX width = 76        ///< Line widths if endOfLine non empty
    );
    void StartEncoding(
      bool useCRLFs,         ///< Use CR, LF pairs in end of line characters.
      PINDEX width = 76      ///< Line widths
    ) { StartEncoding(useCRLFs ? e_CRLF : e_LF, width); }

    /// Incorporate the specified data into the base 64 encoding.
    void ProcessEncoding(
      const PString & str      // String to be encoded
    );
    void ProcessEncoding(
      const char * cstr        // C String to be encoded
    );
    void ProcessEncoding(
      const PBYTEArray & data  // Data block to be encoded
    );
    void ProcessEncoding(
      const void * dataBlock,  // Pointer to data to be encoded
      PINDEX length            // Length of the data block.
    );

    /** Get the partial Base64 string for the data encoded so far.
    
       @return
       Base64 encoded string for the processed data.
     */
    PString GetEncodedString();

    /** Complete the base 64 encoding and return the remainder of the encoded
       Base64 string.
    
       @return
       Base64 encoded string for the processed data.
     */
    PString CompleteEncoding();


    /// Encode the data in memory to Base 64 data returnin the string.
    static PString Encode(
      const PString & str,    ///< String to be encoded to Base64
      Options options = e_LF, ///< Options for encoding.
      PINDEX width = 76       ///< Line widths if options != e_URL
    );
    static PString Encode(
      const PString & str,    ///< String to be encoded to Base64
      const char * endOfLine, ///< String to use for end of line.
      PINDEX width = 76       ///< Line widths if endOfLine non empty
    );
    static PString Encode(
      const char * cstr,      ///< C String to be encoded to Base64
      Options options = e_LF, ///< Options for encoding.
      PINDEX width = 76       ///< Line widths if options != e_URL
    );
    static PString Encode(
      const char * cstr,      ///< C String to be encoded to Base64
      const char * endOfLine, ///< String to use for end of line.
      PINDEX width = 76       ///< Line widths if endOfLine non empty
    );
    static PString Encode(
      const PBYTEArray & data, ///< Data block to be encoded to Base64
      Options options = e_LF,  ///< Options for encoding.
      PINDEX width = 76        ///< Line widths if options != e_URL
    );
    static PString Encode(
      const PBYTEArray & data, ///< Data block to be encoded to Base64
      const char * endOfLine,  ///< String to use for end of line.
      PINDEX width = 76        ///< Line widths if endOfLine non empty
    );
    static PString Encode(
      const void * dataBlock,  ///< Pointer to data to be encoded to Base64
      PINDEX length,           ///< Length of the data block.
      Options options = e_LF,  ///< Options for encoding.
      PINDEX width = 76        ///< Line widths if options != e_URL
    );
    static PString Encode(
      const void * dataBlock,  ///< Pointer to data to be encoded to Base64
      PINDEX length,           ///< Length of the data block.
      const char * endOfLine,  ///< String to use for end of line.
      PINDEX width = 76        ///< Line widths if endOfLine non empty
    );


    void StartDecoding();
    // Begin a base 64 decoding operation, initialising the object instance.

    /** Incorporate the specified data into the base 64 decoding.
    
       @return
       true if block was last in the Base64 encoded string.
     */
    PBoolean ProcessDecoding(
      const PString & str      // String to be encoded
    );
    PBoolean ProcessDecoding(
      const char * cstr        // C String to be encoded
    );

    /** Get the data decoded so far from the Base64 strings processed.
    
       @return
       Decoded data for the processed Base64 string.
     */
    PBoolean GetDecodedData(
      void * dataBlock,    // Pointer to data to be decoded from base64
      PINDEX length        // Length of the data block.
    );
    PBYTEArray GetDecodedData();

    /** Return a flag to indicate that the input was decoded without any
       extraneous or illegal characters in it that were ignored. This does not
       mean that the data is not valid, only that it is suspect.
    
       @return
       Decoded data for the processed Base64 string.
     */
    PBoolean IsDecodeOK() { return m_perfectDecode; }


    /** Convert a printable text string to binary data using the Internet MIME
       standard base 64 content transfer encoding.

       The base64 string is checked and true returned if all perfectly correct.
       If false is returned then the string had extraneous or illegal
       characters in it that were ignored. This does not mean that the data is
       not valid, only that it is suspect.
    
       @return
       Base 64 string decoded from input string.
     */
    static PString Decode(
      const PString & str // Encoded base64 string to be decoded.
    );
    static PBoolean Decode(
      const PString & str, // Encoded base64 string to be decoded.
      PBYTEArray & data    // Converted binary data from base64.
    );
    static PBoolean Decode(
      const PString & str, // Encoded base64 string to be decoded.
      void * dataBlock,    // Pointer to data to be decoded from base64
      PINDEX length        // Length of the data block.
    );



  private:
    void OutputBase64(const BYTE * data);

    PString m_encodedString;
    BYTE    m_saveTriple[3];
    PINDEX  m_saveCount;
    PString m_endOfLine;
    PINDEX  m_maxLineLength;
    PINDEX  m_currentLineLength;
    const char * m_alphabet;

    bool       m_perfectDecode;
    PINDEX     m_quadPosition;
    PBYTEArray m_decodedData;
    PINDEX     m_decodeSize;
};


/**Abstract class for message digests/hashing.
 */
class PMessageDigest : public PObject
{
    PCLASSINFO(PMessageDigest, PObject)
  public:
    /// Create a new message digestor
    PMessageDigest();

    /// Result of digest/hash function
    class Result : public PBYTEArray {
      public:
        virtual void PrintOn(ostream & strm) const;

        bool ConstantTimeCompare(const Result & other) const;

        PString AsBase64(PBase64::Options options = PBase64::e_NoLF) const { return PBase64::Encode(*this, options); }
        PString AsHex() const;
    };

    /// Begin a Message Digest operation, initialising the object instance.
    void Start() { InternalStart(); }

    void Process(
      const void * dataBlock,  ///< Pointer to data to be part of the digest
      PINDEX length            ///< Length of the data block.
    );

    /** Incorporate the specified data into the message digest. */
    void Process(
      const PString & str      ///< String to be part of the digest
    );
    /** Incorporate the specified data into the message digest. */
    void Process(
      const char * cstr        ///< C String to be part of the digest
    );
    /** Incorporate the specified data into the message digest. */
    void Process(
      const PBYTEArray & data  ///< Data block to be part of the digest
    );

    /**
    Complete the message digest and return the magic number result.
    The parameterless form returns the digest code as a Base64 string.
    
    @return
       Base64 encoded digest code for the processed data.
    */
    PString Complete();
    void Complete(
      Result & result   ///< The resultant digest value
    ) { InternalCompleteDigest(result); }

  protected:
    virtual void InternalStart() = 0;
    virtual void InternalProcess(const void * dataBlock, PINDEX length) = 0;
    virtual void InternalCompleteDigest(Result & result) = 0;
};


template <class Digestor> struct PMessageDigestStatics
{
    /** Encode the data in memory to and digest value. */
    static PString Encode(
      const PString & str      ///< String to be encoded to digest
    ) { return Encode(str.GetPointer(), str.GetLength()); }

    /** Encode the data in memory to and digest value. */
    static void Encode(
      const PString & str,            ///< String to be encoded to digest
      PMessageDigest::Result & result ///< The resultant digest code
    ) { Encode(str.GetPointer(), str.GetLength(), result); }

    /** Encode the data in memory to and digest value. */
    static PString Encode(
      const char * cstr        ///< C String to be encoded to digest
    ) { return Encode(cstr, (PINDEX)strlen(cstr)); }

    /** Encode the data in memory to and digest value. */
    static void Encode(
      const char * cstr,       ///< C String to be encoded to digest
      PMessageDigest::Result & result            ///< The resultant digest code
    ) { Encode(cstr, (PINDEX)strlen(cstr), result); }

    /** Encode the data in memory to and digest value. */
    static PString Encode(
      const PBYTEArray & data  ///< Data block to be encoded to digest
    ) { return Encode(data, data.GetSize()); }

    /** Encode the data in memory to and digest value. */
    static void Encode(
      const PBYTEArray & data, ///< Data block to be encoded to digest
      PMessageDigest::Result & result            ///< The resultant digest code
    ) { Encode(data, data.GetSize(), result); }

    /** Encode the data in memory to and digest value. */
    static PString Encode(
      const void * dataBlock,  ///< Pointer to data to be encoded to digest
      PINDEX length            ///< Length of the data block.
    ) {
      PMessageDigest::Result result;
      Encode(dataBlock, length, result);
      return result.AsBase64();
    }

    /** Encode the data in memory to digest value.
    */
    static void Encode(
      const void * dataBlock,  ///< Pointer to data to be encoded to digest
      PINDEX length,           ///< Length of the data block.
      PMessageDigest::Result & result            ///< The resultant digest code
    ) {
      Digestor stomach;
      stomach.Process(dataBlock, length);
      stomach.Complete(result);
    }
};


/** HMAC template class.
 Create a class that implemented a HMAC as per RFC 2104 using an arbitrary hash class
 */

class PHMAC : public PObject
{
    PCLASSINFO(PHMAC, PObject);
  public:
    void SetKey(const char * key)             { InitKey(key, strlen(key)); }
    void SetKey(const PString & key)          { InitKey(key.GetPointer(), key.GetLength()); }
    void SetKey(const PBYTEArray & key)       { InitKey((const BYTE *)key, key.GetSize()); }
    void SetKey(const BYTE * key, PINDEX len) { InitKey(key, len); }

    PString Encode(const void * data, PINDEX len, PBase64::Options options = PBase64::e_NoLF);
    PString Encode(const PBYTEArray & data, PBase64::Options options = PBase64::e_NoLF);
    PString Encode(const PString & str, PBase64::Options options = PBase64::e_NoLF);

    typedef PMessageDigest::Result Result;
    virtual void Process(const void * data, PINDEX len, Result & result);
    virtual void Process(const PBYTEArray & data, Result & result);
    virtual void Process(const PString & str, Result & result);

  protected:
    virtual void InitKey(const void * key, PINDEX len);
    virtual void InternalProcess(const void * data, PINDEX len, PHMAC::Result & result) = 0;

    PBYTEArray m_key;
};


/** MD5 Message Digest.
 A class to produce a Message Digest for a block of text/data using the
 MD5 algorithm as defined in RFC1321 by Ronald Rivest of MIT Laboratory
 for Computer Science and RSA Data Security, Inc.
 */
class PMessageDigest5 : public PMessageDigest, public PMessageDigestStatics<PMessageDigest5>
{
    PCLASSINFO(PMessageDigest5, PMessageDigest)
  public:
    enum { DigestLength = 16 };
    typedef PMessageDigest::Result Code; // Backward compatibility

    /// Create a new message digestor
    PMessageDigest5();

  protected:
    virtual void InternalStart();
    virtual void InternalProcess(const void * dataBlock, PINDEX length);
    virtual void InternalCompleteDigest(Result & result);

  private:
    void Transform(const BYTE * block);

    /// input buffer
    BYTE buffer[64];
    /// state (ABCD)
    DWORD state[4];
    /// number of bits, modulo 2^64 (lsb first)
    PUInt64 count;
};


/** HMAC algorithm using MD5 hashing.
 */
class PHMAC_MD5 : public PHMAC
{
    PCLASSINFO(PHMAC_MD5, PHMAC)
  public:
    enum { BlockSize = 64 };

  protected:
    virtual void InitKey(const void * key, PINDEX len);
    virtual void InternalProcess(const void * data, PINDEX len, PHMAC::Result & result);
};


#if P_SSL

class PMessageDigestSHA : public PMessageDigest
{
    PCLASSINFO(PMessageDigestSHA, PMessageDigest)
  public:
    struct Context;

  protected:
    /// Create a new message digestor
    explicit PMessageDigestSHA(Context * context);

  public:
    ~PMessageDigestSHA();

  protected:
    virtual void InternalStart();
    virtual void InternalProcess(const void * dataBlock, PINDEX length);
    virtual void InternalCompleteDigest(Result & result);
    void Failed();

    Context * m_context;
    enum {
      e_Uninitialised,
      e_Processing,
      e_Failed
    } m_state;

  private:
    PMessageDigestSHA(const PMessageDigestSHA &) : m_context(), m_state() { }
    void operator=(const PMessageDigestSHA &) { }
};


/** A class to produce a Message Digest for a block of text/data using the
 SHA-1 algorithm 
 */
class PMessageDigestSHA1 : public PMessageDigestSHA, public PMessageDigestStatics<PMessageDigestSHA1>
{
    PCLASSINFO(PMessageDigestSHA1, PMessageDigestSHA)
  public:
    enum { DigestLength = 20 };
    PMessageDigestSHA1();
};


/** A class to produce a Message Digest for a block of text/data using the
 SHA-256 algorithm 
 */
class PMessageDigestSHA256 : public PMessageDigestSHA, public PMessageDigestStatics<PMessageDigestSHA256>
{
    PCLASSINFO(PMessageDigestSHA256, PMessageDigestSHA)
  public:
    PMessageDigestSHA256();
};


/** A class to produce a Message Digest for a block of text/data using the
 SHA-384 algorithm 
 */
class PMessageDigestSHA384 : public PMessageDigestSHA, public PMessageDigestStatics<PMessageDigestSHA384>
{
    PCLASSINFO(PMessageDigestSHA384, PMessageDigestSHA)
  public:
    PMessageDigestSHA384();
};


/** A class to produce a Message Digest for a block of text/data using the
 SHA-512 algorithm 
 */
class PMessageDigestSHA512 : public PMessageDigestSHA, public PMessageDigestStatics<PMessageDigestSHA512>
{
    PCLASSINFO(PMessageDigestSHA512, PMessageDigestSHA)
  public:
    PMessageDigestSHA512();
};


class PHMAC_SHA : public PHMAC
{
    PCLASSINFO(PHMAC_SHA, PHMAC)
  protected:
    typedef struct evp_md_st const * Algorithm;

    explicit PHMAC_SHA(Algorithm algo);
    virtual void InternalProcess(const void * data, PINDEX len, PHMAC::Result & result);

    Algorithm m_algorithm;
};


class PHMAC_SHA1 : public PHMAC_SHA
{
    PCLASSINFO(PHMAC_SHA1, PHMAC_SHA)
  public:
    PHMAC_SHA1();
};


class PHMAC_SHA256 : public PHMAC_SHA
{
    PCLASSINFO(PHMAC_SHA256, PHMAC_SHA)
  public:
    PHMAC_SHA256();
};


class PHMAC_SHA384 : public PHMAC_SHA
{
    PCLASSINFO(PHMAC_SHA384, PHMAC_SHA)
  public:
    PHMAC_SHA384();
};


class PHMAC_SHA512 : public PHMAC_SHA
{
    PCLASSINFO(PHMAC_SHA512, PHMAC_SHA)
  public:
    PHMAC_SHA512();
};

#endif // P_SSL


/**This abstract class defines an encryption/decryption algortihm.
A specific algorithm is implemented in a descendent class.
*/
class PCypher : public PObject
{
  PCLASSINFO(PCypher, PObject)

  public:
    /// Mechanism by which sequential blocks are linked.
    enum BlockChainMode {
      ElectronicCodebook,
        ECB = ElectronicCodebook,
      CypherBlockChaining,
        CBC = CypherBlockChaining,
      OutputFeedback,
        OFB = OutputFeedback,
      CypherFeedback,
        CFB = CypherFeedback,
      NumBlockChainModes
    };

  // New functions for class
    /**Encode the data. */
    PString Encode(
      const PString & str       ///< Clear text string to be encoded.
    );
    /**Encode the data. */
    PString Encode(
      const PBYTEArray & clear  ///< Clear text binary data to be encoded.
    );
    /**Encode the data. */
    PString Encode(
      const void * data,        ///< Clear text binary data to be encoded.
      PINDEX length             ///< Number of bytes of data to be encoded.
    );
    /**Encode the data. */
    void Encode(
      const PBYTEArray & clear, ///< Clear text binary data to be encoded.
      PBYTEArray & coded        ///< Encoded data.
    );
    /**Encode the data.
    The data is encoded using the algorithm embodied by the descendent class
    and the key specifed in the construction of the objects instance.

    The first form takes a string and returns an encoded string. The second
    form takes arbitrary binary data bytes and returns an encoded string. In
    both cases the encoded string is always 7 bit printable ASCII suitable
    for use in mail systems etc.

    The final form takes and arbitrary block of bytes and encodes them into
    another block of binary data.
    
    @return
      encoded string.
    */
    void Encode(
      const void * data,        // Clear text binary data to be encoded.
      PINDEX length,            // Number of bytes of data to be encoded.
      PBYTEArray & coded        // Encoded data.
    );

    /**Decode the data. */
    PString Decode(
      const PString & cypher   ///< Base64 Cypher text string to be decoded.
    );
    /**Decode the data. */
    PBoolean Decode(
      const PString & cypher,  ///< Base64 Cypher text string to be decoded.
      PString & clear          ///< Clear text string decoded.
    );
    /**Decode the data. */
    PBoolean Decode(
      const PString & cypher,  ///< Base64 Cypher text string to be decoded.
      PBYTEArray & clear       ///< Clear text binary data decoded.
    );
    /**Decode the data. */
    PINDEX Decode(
      const PString & cypher,  ///< Base64 Cypher text string to be decoded.
      void * data,             ///< Clear text binary data decoded.
      PINDEX length            ///< Maximum number of bytes of data decoded.
    );
    /**Decode the data. */
    PINDEX Decode(
      const PBYTEArray & coded, ///< Encoded data (cyphertext).
      void * data,              ///< Clear text binary data decoded.
      PINDEX length             ///< Maximum number of bytes of data decoded.
    );
    /**Decode the data.
    Decode the data using the algorithm embodied by the descendent class
    and the key specifed in the construction of the objects instance.

    The first form takes a string and returns a decoded string. The second
    form takes an encoded string and returns arbitrary binary data bytes. In
    both cases the encoded string is always 7 bit printable ASCII suitable
    for use in mail systems etc.

    The final form takes and arbitrary block of bytes and decodes them into
    another block of binary data.
    
    @return
      decoded string.
    */
    PBoolean Decode(
      const PBYTEArray & coded, ///< Encoded data (cyphertext).
      PBYTEArray & clear       ///< Clear text binary data decoded.
    );


  protected:
    /**
    Create a new encryption object instance.
    */
    PCypher(
      PINDEX blockSize,          ///< Size of encryption blocks (in bits)
      BlockChainMode chainMode   ///< Block chain mode
    );
    PCypher(
      const void * keyData,    ///< Key for the encryption/decryption algorithm.
      PINDEX keyLength,        ///< Length of the key.
      PINDEX blockSize,        ///< Size of encryption blocks (in bits)
      BlockChainMode chainMode ///< Block chain mode
    );


    /** Initialise the encoding/decoding sequence. */
    virtual void Initialise(
      PBoolean encoding   ///< Flag for encoding/decoding sequence about to start.
    ) = 0;

    /** Encode an n bit block of memory according to the encryption algorithm. */
    virtual void EncodeBlock(
      const void * in,    ///< Pointer to clear n bit block.
      void * out          ///< Pointer to coded n bit block.
    ) = 0;


    /** Dencode an n bit block of memory according to the encryption algorithm. */
    virtual void DecodeBlock(
      const void * in,  ///< Pointer to coded n bit block.
      void * out        ///< Pointer to clear n bit block.
    ) = 0;


    /// Key for the encryption/decryption.
    PBYTEArray key;
    /// Size of each encryption block in bytes
    PINDEX blockSize;
    /// Mode for sequential encryption each block
    BlockChainMode chainMode;
};


/** Tiny Encryption Algorithm.
This class implements the Tiny Encryption Algorithm by David Wheeler and
Roger Needham at Cambridge University.

This is a simple algorithm using a 128 bit binary key and encrypts data in
64 bit blocks.
*/
class PTEACypher : public PCypher
{
  PCLASSINFO(PTEACypher, PCypher)

  public:
    struct Key {
      BYTE value[16];
    };

    /**
    Create a new TEA encryption object instance. The parameterless version
    automatically generates a new, random, key.
    */
    PTEACypher(
      BlockChainMode chainMode = ElectronicCodebook   ///< Block chain mode
    );
    PTEACypher(
      const Key & keyData,     ///< Key for the encryption/decryption algorithm.
      BlockChainMode chainMode = ElectronicCodebook   ///< Block chain mode
    );


    /** Set the key used by this encryption method. */
    void SetKey(
      const Key & newKey    ///< Variable to take the key used by cypher.
    );

    /** Get the key used by this encryption method. */
    void GetKey(
      Key & newKey    ///< Variable to take the key used by cypher.
    ) const;


    /** Generate a new key suitable for use for encryption using random data. */
    static void GenerateKey(
      Key & newKey    ///< Variable to take the newly generated key.
    );


  protected:
    /** Initialise the encoding/decoding sequence. */
    virtual void Initialise(
      PBoolean encoding   ///< Flag for encoding/decoding sequence about to start.
    );

    /** Encode an n bit block of memory according to the encryption algorithm. */
    virtual void EncodeBlock(
      const void * in,  ///< Pointer to clear n bit block.
      void * out        ///< Pointer to coded n bit block.
    );

    /** Decode an n bit block of memory according to the encryption algorithm. */
    virtual void DecodeBlock(
      const void * in,  ///< Pointer to coded n bit block.
      void * out        ///< Pointer to clear n bit block.
    );

  private:
    DWORD k0, k1, k2, k3;
};


#ifdef P_CONFIG_FILE

class PSecureConfig : public PConfig
{
  PCLASSINFO(PSecureConfig, PConfig)
/* This class defines a set of configuration keys which may be secured by an
   encrypted hash function. Thus values contained in keys specified by this
   class cannot be changed without invalidating the hash function.
 */

  public:
    PSecureConfig(
      const PTEACypher::Key & productKey,    // Key to decrypt validation code.
      const PStringArray    & securedKeys,   // List of secured keys.
      Source src = Application        // Standard source for the configuration.
    );
    PSecureConfig(
      const PTEACypher::Key & productKey,   // Key to decrypt validation code.
      const char * const * securedKeyArray, // List of secured keys.
      PINDEX count,                         // Number of secured keys in list.
      Source src = Application        // Standard source for the configuration.
    );
    /* Create a secured configuration. The default section for the
       configuration keys is "Secured Options", the default security key is
       "Validation" and the defualt prefix string is "Pending:".

       The user can descend from this class and change any of the member
       variable for the names of keys or the configuration file section.
     */


  // New functions for class
    const PStringArray & GetSecuredKeys() const { return securedKeys; }
    /* Get the list of secured keys in the configuration file section.

       @return
       Array of  strings for the secured keys.
     */

    const PString & GetSecurityKey() const { return securityKey; }
    /* Get the security keys name in the configuration file section.

       @return
       String for the security values key.
     */

    const PString & GetExpiryDateKey() const { return expiryDateKey; }
    /* Get the expiry date keys name in the configuration file section.

       @return
       String for the expiry date values key.
     */

    const PString & GetOptionBitsKey() const { return optionBitsKey; }
    /* Get the Option Bits keys name in the configuration file section.

       @return
       String for the Option Bits values key.
     */

    const PString & GetPendingPrefix() const { return pendingPrefix; }
    /* Get the pending prefix name in the configuration file section.

       @return
       String for the pending prefix.
     */

    void GetProductKey(
      PTEACypher::Key & productKey  // Variable to receive the product key.
    ) const;
    /* Get the pending prefix name in the configuration file section.

       @return
       String for the pending prefix.
     */


    enum ValidationState {
      Defaults,
      Pending,
      IsValid,
      Expired,
      Invalid
    };
    ValidationState GetValidation() const;
    /* Check the current values attached to the keys specified in the
       constructor against an encoded validation key.

       @return
       State of the validation keys.
     */

    PBoolean ValidatePending();
    /* Validate a pending secured option list for the product. All secured
       keys with the <CODE>pendingPrefix</CODE> name will be checked against
       the value of the field <CODE>securityKey</CODE>. If they match then
       they are copied to the secured variables.

       @return
       true if secure key values are valid.
     */

    void ResetPending();
    /* "Unvalidate" a security configuration going back to a pending state,
       usually used after an <CODE>Invalid</CODE> response was recieved from
       the <A>GetValidation()</A> function.
     */


  protected:
    PTEACypher::Key productKey;
    PStringArray    securedKeys;
    PString         securityKey;
    PString         expiryDateKey;
    PString         optionBitsKey;
    PString         pendingPrefix;
};

#endif // P_CONFIG_FILE

#endif // P_CYPHER

#endif // PTLIB_CYPHER_H


// End Of File ///////////////////////////////////////////////////////////////
