/*
 * inetprot.cxx
 *
 * Internet Protocol ancestor class.
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

#ifdef __GNUC__
#pragma implementation "inetprot.h"
#pragma implementation "mime.h"
#endif

#include <ptlib.h>
#include <ptlib/sockets.h>
#include <ptclib/inetprot.h>
#include <ptclib/mime.h>
#include <ptclib/random.h>


static const char * CRLF = "\r\n";


#define new PNEW


//////////////////////////////////////////////////////////////////////////////
// PInternetProtocol

PInternetProtocol::PInternetProtocol(const char * svcName,
                                     PINDEX cmdCount,
                                     char const * const * cmdNames)
  : defaultServiceName(svcName),
    commandNames(cmdCount, cmdNames, true),
    readLineTimeout(0, 10)   // 10 seconds
{
  SetReadTimeout(PTimeInterval(0, 0, 10));  // 10 minutes
  stuffingState = DontStuff;
  newLineToCRLF = true;
  unReadCount = 0;
}


void PInternetProtocol::SetReadLineTimeout(const PTimeInterval & t)
{
  readLineTimeout = t;
}


PBoolean PInternetProtocol::Read(void * buf, PINDEX len)
{
  if (unReadCount == 0) {
    char readAhead[1000];
    if (!PIndirectChannel::Read(readAhead, sizeof(readAhead)))
      return false;

    UnRead(readAhead, GetLastReadCount());
  }

  SetLastReadCount(PMIN(unReadCount, len));
  const char * unReadPtr = ((const char *)unReadBuffer)+unReadCount;
  char * bufptr = (char *)buf;
  while (unReadCount > 0 && len > 0) {
    *bufptr++ = *--unReadPtr;
    unReadCount--;
    len--;
  }

  if (len > 0) {
    PINDEX saveCount = GetLastReadCount();
    PIndirectChannel::Read(bufptr, len);
    SetLastReadCount(GetLastReadCount() + saveCount);
  }

  return GetLastReadCount() > 0;
}


int PInternetProtocol::ReadChar()
{
  if (unReadCount == 0) {
    char readAhead[1000];
    if (!PIndirectChannel::Read(readAhead, sizeof(readAhead)))
      return -1;

    UnRead(readAhead, GetLastReadCount());
    if (unReadCount == 0)
      return -1;
  }

  SetLastReadCount(1);
  return (unReadBuffer[--unReadCount]&0xff);
}


PBoolean PInternetProtocol::Write(const void * buf, PINDEX len)
{
  if (len == 0 || stuffingState == DontStuff)
    return PIndirectChannel::Write(buf, len);

  PINDEX totalWritten = 0;
  const char * base = (const char *)buf;
  const char * current = base;
  while (len-- > 0) {
    switch (stuffingState) {
      case StuffIdle :
        switch (*current) {
          case '\r' :
            stuffingState = StuffCR;
            break;

          case '\n' :
            if (newLineToCRLF) {
              if (current > base) {
                if (!PIndirectChannel::Write(base, current - base))
                  return false;
                totalWritten += GetLastWriteCount();
              }
              if (!PIndirectChannel::Write("\r", 1))
                return false;
              totalWritten += GetLastWriteCount();
              base = current;
            }
        }
        break;

      case StuffCR :
        stuffingState = *current != '\n' ? StuffIdle : StuffCRLF;
        break;

      case StuffCRLF :
        if (*current == '.') {
          if (current > base) {
            if (!PIndirectChannel::Write(base, current - base))
              return false;
            totalWritten += GetLastWriteCount();
          }
          if (!PIndirectChannel::Write(".", 1))
            return false;
          totalWritten += GetLastWriteCount();
          base = current;
        }
        // Then do default state

      default :
        stuffingState = StuffIdle;
        break;
    }
    current++;
  }

  if (current > base) {  
    if (!PIndirectChannel::Write(base, current - base))  
      return false;  
    totalWritten += GetLastWriteCount();  
  }  
  
  return SetLastWriteCount(totalWritten) > 0;
}


PBoolean PInternetProtocol::AttachSocket(PIPSocket * socket)
{
  if (socket->IsOpen()) {
    if (Open(socket))
      return true;
    Close();
    SetErrorValues(Miscellaneous, 0x41000000);
  }
  else {
    SetErrorValues(socket->GetErrorCode(), socket->GetErrorNumber());
    delete socket;
  }

  return false;
}


PBoolean PInternetProtocol::Connect(const PString & address, WORD port)
{
  if (port == 0)
    return Connect(address, defaultServiceName);

  if (readTimeout == PMaxTimeInterval)
    return AttachSocket(new PTCPSocket(address, port));

  PTCPSocket * s = new PTCPSocket(port);
  s->SetReadTimeout(readTimeout);
  s->Connect(address);
  return AttachSocket(s);
}


PBoolean PInternetProtocol::Connect(const PString & address, const PString & service)
{
  if (readTimeout == PMaxTimeInterval)
    return AttachSocket(new PTCPSocket(address, service));

  PTCPSocket * s = new PTCPSocket;
  s->SetReadTimeout(readTimeout);
  s->SetPort(service);
  s->Connect(address);
  return AttachSocket(s);
}


PBoolean PInternetProtocol::Accept(PSocket & listener)
{
  if (readTimeout == PMaxTimeInterval)
    return AttachSocket(new PTCPSocket(listener));

  PTCPSocket * s = new PTCPSocket;
  s->SetReadTimeout(readTimeout);
  s->Accept(listener);
  return AttachSocket(s);
}


const PString & PInternetProtocol::GetDefaultService() const
{
  return defaultServiceName;
}


PIPSocket * PInternetProtocol::GetSocket() const
{
  PChannel * channel = GetBaseReadChannel();
  if (channel != NULL && PIsDescendant(channel, PIPSocket))
    return (PIPSocket *)channel;
  return NULL;
}


PBoolean PInternetProtocol::WriteLine(const PString & line)
{
  if (line.FindOneOf(CRLF) == P_MAX_INDEX)
    return WriteString(line + CRLF);

  PStringArray lines = line.Lines();
  for (PINDEX i = 0; i < lines.GetSize(); i++)
    if (!WriteString(lines[i] + CRLF))
      return false;

  return true;
}


PBoolean PInternetProtocol::ReadLine(PString & line, PBoolean allowContinuation)
{
  if (!line.SetMinSize(1000))
    return false;

  PINDEX count = 0;
  PBoolean gotEndOfLine = false;

  int c = ReadChar();
  if (c < 0)
    return false;

  PTimeInterval oldTimeout = GetReadTimeout();
  SetReadTimeout(readLineTimeout);

  while (c >= 0 && !gotEndOfLine) {
    switch (c) {
      case '\b' :
      case '\177' :
        if (count > 0)
          count--;
        c = ReadChar();
        break;

      case '\r' :
        c = ReadChar();
        switch (c) {
          case -1 :
          case '\n' :
            break;

          case '\r' :
            c = ReadChar();
            if (c == '\n')
              break;
            UnRead(c);
            c = '\r';
            // Then do default case

          default :
            UnRead(c);
        }
        // Then do line feed case

      case '\n' :
        if (count == 0 || !allowContinuation || (c = ReadChar()) < 0)
          gotEndOfLine = true;
        else if (c != ' ' && c != '\t') {
          UnRead(c);
          gotEndOfLine = true;
        }
        break;

      default :
        if (count >= line.GetSize())
          line.SetSize(count + 100);
        line[count++] = (char)c;
        c = ReadChar();
    }
  }

  SetReadTimeout(oldTimeout);

  if (count > 0)
    line.MakeMinimumSize(count);
  else
    line.MakeEmpty();

  return gotEndOfLine;
}


void PInternetProtocol::UnRead(int ch)
{
  unReadBuffer.SetSize((unReadCount+256)&~255);
  unReadBuffer[unReadCount++] = (char)ch;
}


void PInternetProtocol::UnRead(const PString & str)
{
  UnRead((const char *)str, str.GetLength());
}


void PInternetProtocol::UnRead(const void * buffer, PINDEX len)
{
  char * unreadptr =
               unReadBuffer.GetPointer((unReadCount+len+255)&~255)+unReadCount;
  const char * bufptr = ((const char *)buffer)+len;
  unReadCount += len;
  while (len-- > 0)
    *unreadptr++ = *--bufptr;
}


PBoolean PInternetProtocol::WriteCommand(PINDEX cmdNumber, const PString & param)
{
  if (cmdNumber >= commandNames.GetSize())
    return false;

  *this << commandNames[cmdNumber];

  if (!param.IsEmpty())
    *this << ' ' << param;

  *this << CRLF << ::flush;
  return good();
}


PBoolean PInternetProtocol::WriteCommand(PINDEX cmdNumber, const PString & param, const PMIMEInfo & mime)
{
  if (cmdNumber >= commandNames.GetSize())
    return false;

  *this << commandNames[cmdNumber] << ' ' << param << CRLF << setfill('\r') << mime << ::flush;
  return good();
}


PBoolean PInternetProtocol::ReadCommand(PINDEX & num, PString & args)
{
  do {
    if (!ReadLine(args))
      return false;
  } while (args.IsEmpty());

  PINDEX endCommand = args.Find(' ');
  if (endCommand == P_MAX_INDEX)
    endCommand = args.GetLength();
  PCaselessString cmd = args.Left(endCommand);

  num = commandNames.GetValuesIndex(cmd);
  if (num != P_MAX_INDEX)
    args = args.Mid(endCommand+1);

  return true;
}


PBoolean PInternetProtocol::ReadCommand(PINDEX & num, PString & args, PMIMEInfo & mime)
{
  if (!ReadCommand(num, args))
    return false;

  return mime.Read(*this);
}


PBoolean PInternetProtocol::WriteResponse(unsigned code, const PString & info)
{
  return WriteResponse(psprintf("%03u", code), info);
}


PBoolean PInternetProtocol::WriteResponse(const PString & code,
                                       const PString & info)
{
  if (info.FindOneOf(CRLF) == P_MAX_INDEX)
    return WriteString((code & info) + CRLF);

  PStringArray lines = info.Lines();
  PINDEX i;
  for (i = 0; i < lines.GetSize()-1; i++)
    if (!WriteString(code + '-' + lines[i] + CRLF))
      return false;

  return WriteString((code & lines[i]) + CRLF);
}


PBoolean PInternetProtocol::ReadResponse()
{
  PString line;
  if (!ReadLine(line))
    return SetLastResponse(-1, "Response first line", LastReadError);

  PINDEX continuePos = ParseResponse(line);
  if (continuePos == 0)
    return true;

  PString info;
  PString prefix = line.Left(continuePos);
  char continueChar = line[continuePos];
  while (line[continuePos] == continueChar ||
         (!isdigit(line[(PINDEX)0]) && strncmp(line, prefix, continuePos) != 0)) {
    info += '\n';
    if (!ReadLine(line))
      return SetLastResponse(-1, info, LastReadError);

    if (line.Left(continuePos) == prefix)
      info += line.Mid(continuePos+1);
    else
      info += line;
  }

  return SetLastResponse(0, info, LastReadError);
}


PBoolean PInternetProtocol::ReadResponse(int & code, PString & info)
{
  bool retval = ReadResponse();

  code = GetLastResponseCode();
  info = GetLastResponseInfo();

  return retval;
}


PBoolean PInternetProtocol::ReadResponse(int & code, PString & info, PMIMEInfo & mime)
{
  if (!ReadResponse(code, info))
    return false;

  return mime.Read(*this);
}


PINDEX PInternetProtocol::ParseResponse(const PString & line)
{
  PINDEX endCode = line.FindOneOf(" -");
  if (endCode == P_MAX_INDEX) {
    SetLastResponse(-1, line);
    return 0;
  }

  SetLastResponse(line.Left(endCode).AsInteger(), line.Mid(endCode+1));
  return line[endCode] != ' ' ? endCode : 0;
}


int PInternetProtocol::ExecuteCommand(PINDEX cmd)
{
  return ExecuteCommand(cmd, PString());
}


int PInternetProtocol::ExecuteCommand(PINDEX cmd,
                                       const PString & param)
{
  PTimeInterval oldTimeout = GetReadTimeout();
  SetReadTimeout(0);
  while (ReadChar() >= 0)
    ;
  SetReadTimeout(oldTimeout);
  return WriteCommand(cmd, param) && ReadResponse() ? m_lastResponseCode : -1;
}


bool PInternetProtocol::SetLastResponse(int code, const PString & info, ErrorGroup group)
{
  m_lastResponseCode = code;
  m_lastResponseInfo = info;

  if (code == 0 || (code >= 200 && code < 300))
    return true;

  if (code >= 300)
    return false;

  Errors errCode = GetErrorCode(group);
  if (errCode== NoError && group != LastReadError && group != LastWriteError)
    return SetErrorValues(ProtocolFailure, code, group);

  PString errText = GetErrorText(group);
  int errNum = GetErrorNumber(group);
  if (errText.IsEmpty() && errNum == 0)
    errText = "Remote shutdown";
  else if (errText.IsEmpty())
    errText.sprintf("errno=%i", errNum);
  else
    errText.sprintf(" (errno=%i)", errNum);
  m_lastResponseInfo &= errText;
  return false;
}


//////////////////////////////////////////////////////////////////////////////
// PMIMEInfo

PMIMEInfo::PMIMEInfo(istream & strm)
{
  ReadFrom(strm);
}


PMIMEInfo::PMIMEInfo(PInternetProtocol & socket)
{
  Read(socket);
}


PMIMEInfo::PMIMEInfo(const PStringToString & dict)
  : PStringOptions(dict)
{
}


PMIMEInfo::PMIMEInfo(const PString & str)
{
  PStringStream strm(str);
  ReadFrom(strm);
}


PString PMIMEInfo::AsString() const
{
  PStringStream strm;
  PrintOn(strm);
  return strm;
}


void PMIMEInfo::PrintOn(ostream &strm) const
{
  bool crlf = strm.fill() == '\r';
  PrintContents(strm);
  if (crlf)
    strm << '\r';
  strm << '\n';
}

ostream & PMIMEInfo::PrintContents(ostream &strm) const
{
  bool output_cr = strm.fill() == '\r';
  std::streamsize indent = strm.width();
  strm.fill(' ');
  for (const_iterator it = begin(); it != end(); ++it) {
    PString name = it->first + ": ";
    PString value = it->second;
    if (value.FindOneOf("\r\n") != P_MAX_INDEX) {
      PStringArray vals = value.Lines();
      for (PINDEX j = 0; j < vals.GetSize(); j++) {
        if (indent > 0)
          strm << setw(indent) << " ";
        strm << name << vals[j];
        if (output_cr)
          strm << '\r';
        strm << '\n';
      }
    }
    else {
      if (indent > 0)
        strm << setw(indent) << " ";
      strm << name << value;
      if (output_cr)
        strm << '\r';
      strm << '\n';
    }
  }
  return strm;
}


void PMIMEInfo::ReadFrom(istream &strm)
{
  RemoveAll();

  PString line;
  PString lastLine;
  bool incomplete = true;
  while (strm.good()) {
    strm >> line;
    if (line.IsEmpty()) {
      incomplete = false;
      break;
    }
    if (line[(PINDEX)0] == ' ' || line[(PINDEX)0] == '\t') // RFC 2822 section 2.2.2 & 2.2.3
      lastLine += line;
    else {
      AddMIME(lastLine);
      lastLine = line;
    }
  }

  if (!lastLine.IsEmpty())
    AddMIME(lastLine);

  if (incomplete)
    strm.setstate(ios::failbit);
}


PBoolean PMIMEInfo::Read(PInternetProtocol & socket)
{
  RemoveAll();

  PString line;
  while (socket.ReadLine(line, true)) {
    if (line.IsEmpty())
      return true;
    AddMIME(line);
  }

  return false;
}


bool PMIMEInfo::AddMIME(const PString & line)
{
  PINDEX colonPos = line.Find(':');
  if (colonPos == P_MAX_INDEX)
    return false;

  PINDEX dataPos = colonPos+1;
  while (isspace(line[dataPos]))
    ++dataPos;

  return AddMIME(line.Left(colonPos).Trim(), line.Mid(dataPos));
}


bool PMIMEInfo::InternalAddMIME(const PString & fieldName, const PString & fieldValue)
{
  PString * str = GetAt(fieldName);
  if (str == NULL)
    return SetAt(fieldName, fieldValue);

  *str += '\n';
  *str += fieldValue;
  return true;
}


bool PMIMEInfo::AddMIME(const PMIMEInfo & mime)
{
  for (const_iterator it = mime.begin(); it != mime.end(); ++it) {
    if (!AddMIME(it->first, it->second))
      return false;
  }

  return true;
}


PBoolean PMIMEInfo::Write(PInternetProtocol & socket) const
{
  for (const_iterator it = begin(); it != end(); ++it) {
    PString name = it->first + ": ";
    PString value = it->second;
    if (value.FindOneOf("\r\n") != P_MAX_INDEX) {
      PStringArray vals = value.Lines();
      for (PINDEX j = 0; j < vals.GetSize(); j++) {
        if (!socket.WriteLine(name + vals[j]))
          return false;
      }
    }
    else {
      if (!socket.WriteLine(name + value))
        return false;
    }
  }

  return socket.WriteString(CRLF);
}


bool PMIMEInfo::ParseComplex(const PString & fieldValue, PStringToString & info)
{
  info.RemoveAll();

  PStringArray fields = fieldValue.Lines();
  for (PINDEX f = 0; f < fields.GetSize(); ++f) {
    PString field = fields[f];

    PINDEX tagSep = 0;
    while (tagSep != P_MAX_INDEX) {
      if (field[tagSep] == ',') {
        while (isspace(field[tagSep]) || field[tagSep] == ',')
          tagSep++;
        if (field[tagSep] == '\0')
          break;
      }

      if (field[tagSep] == ';')
        continue;

      PString keyPrefix;

      if (!info.IsEmpty()) {
        unsigned count = 0;
        do {
          keyPrefix = psprintf("%u:", ++count);
        } while (info.Contains(keyPrefix));
      }

      if (field[tagSep] != '<') {
        PINDEX nextSep = field.FindOneOf(";,", tagSep);
        info.SetAt(keyPrefix, field(tagSep, nextSep-1).Trim());
        tagSep = nextSep;
      }
      else {
        PINDEX endtoken = field.Find('>', tagSep);
        info.SetAt(keyPrefix, field(tagSep+1, endtoken-1));
        tagSep = field.FindOneOf(";,", endtoken);
      }

      while (tagSep != P_MAX_INDEX && field[tagSep] != ',') {
        ++tagSep; // Skip past ';'
        PINDEX pos = field.FindOneOf("=;,", tagSep);
        PCaselessString tag = field(tagSep, pos-1).Trim();

        if (pos == P_MAX_INDEX || field[pos] == ',') {
          info.SetAt(keyPrefix+tag, PString::Empty());
          break;
        }

        if (field[pos] == ';') {
          info.SetAt(keyPrefix+tag, PString::Empty());
          tagSep = pos;
          continue;
        }

        do {
          ++pos;
        } while (isspace(field[pos]));

        if (field[pos] != '"') {
          tagSep = field.FindOneOf(";,", pos);
          info.SetAt(keyPrefix+tag, PCaselessString(field(pos, tagSep-1).RightTrim()));
          continue;
        }

        ++pos;
        PINDEX quote = pos;
        while ((quote = field.Find('"', quote)) != P_MAX_INDEX && field[quote-1] == '\\')
          ++quote;

        PString value = field(pos, quote-1);
        value.Replace("\\", "", true);
        info.SetAt(keyPrefix+tag, value);

        tagSep = field.FindOneOf(";,", quote);
      }
    }
  }

  return !info.IsEmpty();
}


bool PMIMEInfo::DecodeMultiPartList(PMultiPartList & parts, const PString & body, const PCaselessString & key) const
{
  PStringToString info;
  return GetComplex(key, info) && parts.Decode(body, info);
}


void PMIMEInfo::AddMultiPartList(PMultiPartList & parts, const PCaselessString & (*key)())
{
  switch (parts.GetSize()) {
    case 0 :
      return;

    case 1 :
      Set(key, parts.front().m_contentType);
      break;

    default :
      Set(key, "multipart/mixed;boundary="+parts.GetBoundary());
      break;
  }

  for (PMultiPartList::iterator it = parts.begin(); it != parts.end(); ++it)
    it->SetMIME();
}


static const PStringToString::Initialiser DefaultContentTypes[] = {
  { ".txt", "text/plain" },
  { ".text", "text/plain" },
  { ".log", "text/plain" },
  { ".html", "text/html" },
  { ".htm", "text/html" },
  { ".csv", "text/csv" },
  { ".css", "text/css" },
  { ".js", "application/javascript" },
  { ".xml", "application/xml" },
  { ".json", "application/json" },
  { ".aif", "audio/aiff" },
  { ".aiff", "audio/aiff" },
  { ".au", "audio/basic" },
  { ".snd", "audio/basic" },
  { ".wav", "audio/wav" },
  { ".gif", "image/gif" },
  { ".png", "image/png" },
  { ".xbm", "image/x-bitmap" },
  { ".tif", "image/tiff" },
  { ".tiff", "image/tiff" },
  { ".jpg", "image/jpeg" },
  { ".jpe", "image/jpeg" },
  { ".jpeg", "image/jpeg" },
  { ".avi", "video/avi" },
  { ".mpg", "video/mpeg" },
  { ".mpeg", "video/mpeg" },
  { ".qt", "video/quicktime" },
  { ".mov", "video/quicktime" }
};

PStringToString & PMIMEInfo::GetContentTypes()
{
  static PStringToString contentTypes(PARRAYSIZE(DefaultContentTypes),
                                      DefaultContentTypes,
                                      true);
  return contentTypes;
}


void PMIMEInfo::SetAssociation(const PStringToString & allTypes, PBoolean merge)
{
  PStringToString & types = GetContentTypes();
  if (!merge)
    types.RemoveAll();
  for (const_iterator it = allTypes.begin(); it != allTypes.end(); ++it)
    types.SetAt(it->first, it->second);
}


PString PMIMEInfo::GetContentType(const PString & fType)
{
  if (fType.IsEmpty())
    return PMIMEInfo::TextPlain();

  PStringToString & types = GetContentTypes();
  if (types.Contains(fType))
    return types[fType];

  return "application/octet-stream";
}


const PCaselessString & PMIMEInfo::ContentTypeTag()             { static const PConstCaselessString s("Content-Type");              return s; }
const PCaselessString & PMIMEInfo::ContentDispositionTag()      { static const PConstCaselessString s("Content-Disposition");       return s; }
const PCaselessString & PMIMEInfo::ContentTransferEncodingTag() { static const PConstCaselessString s("Content-Transfer-Encoding"); return s; }
const PCaselessString & PMIMEInfo::ContentDescriptionTag()      { static const PConstCaselessString s("Content-Description");       return s; }
const PCaselessString & PMIMEInfo::ContentIdTag()               { static const PConstCaselessString s("Content-ID");                return s; }

const PCaselessString & PMIMEInfo::TextPlain()                  { static const PConstCaselessString s("text/plain");                return s; }
const PCaselessString & PMIMEInfo::TextHTML()                   { static const PConstCaselessString s("text/html");                 return s; }
const PCaselessString & PMIMEInfo::ApplicationJSON()            { static const PConstCaselessString s("application/json");          return s; }


//////////////////////////////////////////////////////////////////////////////

PMultiPartList::PMultiPartList()
  : m_boundary(PRandom::String(20))
{
}


PMultiPartList::PMultiPartList(const PString & data, const PString & contentType, const PString & disposition)
{
  Append(new PMultiPartInfo(data, contentType, disposition));
}


static PINDEX FindBoundary(const PString & boundary, const char * & bodyPtr, PINDEX & bodyLen)
{
  PINDEX boundaryLen = boundary.GetLength();
  const char * base = bodyPtr;
  const char * found;
  while (bodyLen >= boundaryLen && (found = (const char *)memchr(bodyPtr, boundary[(PINDEX)0], bodyLen)) != NULL) {
    PINDEX skip = found - bodyPtr + 1;
    bodyPtr += skip;
    bodyLen -= skip;

    if (bodyLen >= boundaryLen && memcmp(found, (const char *)boundary, boundaryLen) == 0) {
      bodyPtr += boundaryLen;
      bodyLen -= boundaryLen;
      if (bodyLen < 2)
        return P_MAX_INDEX;

      if (bodyPtr[0] == '\r') {
        ++bodyPtr;
        --bodyLen;
      }
      if (bodyPtr[0] == '\n') {
        ++bodyPtr;
        --bodyLen;
      }

      PINDEX len = found - base;
      if (len > 0 && *(found-1) == '\n') {
        --len;
        if (len > 0 && *(found-2) == '\r')
          --len;
      }
      return len;
    }
  }

  return P_MAX_INDEX;
}

bool PMultiPartList::Decode(const PString & entityBody, const PStringToString & contentInfo)
{
  RemoveAll();

  if (entityBody.IsEmpty())
    return false;

  PCaselessString multipartContentType = contentInfo(PString::Empty());
  if (multipartContentType.NumCompare("multipart/") != EqualTo)
    return false;

  if (!contentInfo.Contains("boundary")) {
    PTRACE(2, "MIME\tNo boundary in multipart Content-Type");
    return false;
  }

  PCaselessString startContentId, startContentType;
  if (multipartContentType == "multipart/related") {
    startContentId = contentInfo("start");
    startContentType = contentInfo("type");
  }

  PString boundary = "--" + contentInfo["boundary"];

  // split body into parts, assuming binary data
  const char * bodyPtr = (const char *)entityBody;
  PINDEX bodyLen = entityBody.GetSize()-1;

  // Find first boundary
  if (FindBoundary(boundary, bodyPtr, bodyLen) == P_MAX_INDEX) {
    PTRACE(2, "MIME\tNo boundary found in multipart body");
    return false;
  }

  for (;;) {
    const char * partPtr = bodyPtr;
    PINDEX partLen = FindBoundary(boundary, bodyPtr, bodyLen);
    if (partLen == P_MAX_INDEX)
      break;

    // create the new part info
    PMultiPartInfo * info = new PMultiPartInfo;

    // read MIME information
    PStringStream strm(PString(partPtr, partLen));
    info->m_mime.ReadFrom(strm);

    // Skip over MIME
    partPtr += (int)strm.tellp();
    partLen -= (int)strm.tellp();

    // Check transfer encoding
    PStringToString typeInfo;
    info->m_mime.GetComplex(PMIMEInfo::ContentTypeTag, typeInfo);
    PCaselessString encoding = info->m_mime.GetString(PMIMEInfo::ContentTransferEncodingTag);

    // save the entity body, being careful of binary files
#if P_CYPHER
    if (encoding == "base64")
      PBase64::Decode(PString(partPtr, partLen), info->m_binaryBody);
    else
#endif
#ifdef P_HAS_WCHAR
    if ((typeInfo("charset") *= "UCS-2") || (typeInfo("charset") *= "UTF-16")) {
      PWCharArray wide(partLen/2);
      for (PINDEX i = 0; i < wide.GetSize(); ++i)
        wide[i] = ((const wchar_t *)partPtr)[i];
      info->m_textBody = wide;
    }
    else
#endif
    if (encoding == "7bit" || encoding == "8bit" || (typeInfo("charset") *= "UTF-8") || memchr(partPtr, 0, partLen) == NULL)
      info->m_textBody = PString(partPtr, partLen);
    else
      info->m_binaryBody = PBYTEArray((const BYTE *)partPtr, partLen);

    // add the data to the array
    if (startContentId.IsEmpty() || startContentId != info->m_mime.GetString(PMIMEInfo::ContentIdTag))
      Append(info);
    else {
      // Make sure start Content Type is set
      if (!info->m_mime.Contains(PMIMEInfo::ContentTypeTag))
        info->m_mime.SetAt(PMIMEInfo::ContentTypeTag, startContentType);

      // Make sure "start" mime entry is at the beginning of list
      Prepend(info);
      startContentId.MakeEmpty();
    }

  }

  return !IsEmpty();
}


PString PMultiPartList::AsString() const
{
  PStringStream strm;
  strm << *this;
  return strm;
}


void PMultiPartList::PrintOn(ostream & strm) const
{
  if (IsEmpty())
    return;

  if (GetSize() == 1) {
    strm << front();
    return;
  }

  PAssert(!m_boundary.IsEmpty(), PLogicError);

  for (const_iterator it = begin(); it != end(); ++it)
    strm << "--" << m_boundary << "\r\n" << setfill('\r') << it->m_mime << *it << "\r\n";
  strm << "--" << m_boundary << "--\r\n";
}


PMultiPartInfo::PMultiPartInfo(const PString & data, const PString & contentType, const PString & disposition)
  : m_contentType(contentType)
  , m_charset("UTF-8")
  , m_encoding("8bit")
  , m_disposition(disposition)
  , m_textBody(data)
{
}


PMultiPartInfo::PMultiPartInfo(const PBYTEArray & data, const PString & contentType, const PString & disposition)
  : m_contentType(contentType)
  , m_encoding("binary")
  , m_disposition(disposition)
  , m_binaryBody(data)
{
}


void PMultiPartInfo::SetMIME()
{
  if (!m_mime.Has(PMIMEInfo::ContentTypeTag)) {
    if (m_charset.IsEmpty())
      m_mime.Set(PMIMEInfo::ContentTypeTag, m_contentType);
    else
      m_mime.Set(PMIMEInfo::ContentTypeTag, PSTRSTRM(m_contentType << "; charset=" << m_charset));
  }

  if (!m_mime.Has(PMIMEInfo::ContentTransferEncodingTag))
    m_mime.Set(PMIMEInfo::ContentTransferEncodingTag, m_encoding);

  if (!m_disposition.IsEmpty() && m_mime.Has(PMIMEInfo::ContentDispositionTag))
    m_mime.Set(PMIMEInfo::ContentDispositionTag, m_disposition);
}


void PMultiPartInfo::PrintOn(ostream & strm) const
{
#if P_CYPHER
  if (m_encoding == "base64")
    strm << PBase64::Encode(m_binaryBody);
  else
#endif
  if (m_encoding == "8bit")
    strm << m_textBody;
  else if (m_encoding == "7bit") {
    for (PINDEX i = 0; i < m_textBody.GetLength(); ++i) {
      if ((m_textBody[i]&0x80) == 0)
        strm << m_textBody[i];
    }
  }
  else {
#ifdef P_HAS_WCHAR
    if (m_charset == "UTF-16" || m_charset == "UCS-2") {
      PWCharArray wide = m_textBody.AsWide();
      strm.write((const char *)wide.GetPointer(), (wide.GetSize()-1)*sizeof(wchar_t));
    }
    else
#endif
      strm.write((const char *)(const BYTE *)m_binaryBody, m_binaryBody.GetSize());
  }
}


// End Of File ///////////////////////////////////////////////////////////////
