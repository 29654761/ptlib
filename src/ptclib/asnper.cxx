/*
 * asnper.cxx
 *
 * Abstract Syntax Notation 1 Encoding Rules
 *
 * Portable Windows Library
 */

///////////////////////////////////////////////////////////////////////

PBoolean PPER_Stream::NullDecode(PASN_Null &)
{
  return true;
}


void PPER_Stream::NullEncode(const PASN_Null &)
{
}

///////////////////////////////////////////////////////////////////////

PBoolean PASN_ConstrainedObject::ConstrainedLengthDecode(PPER_Stream & strm, unsigned & length)
{
  // The execution order is important in the following. The SingleBitDecode() function
  // must be called if extendable is true, no matter what.
  if ((m_extendable && strm.SingleBitDecode()) || constraint == Unconstrained)
    return strm.LengthDecode(0, INT_MAX, length);
  else
    return strm.LengthDecode(lowerLimit, upperLimit, length);
}


void PASN_ConstrainedObject::ConstrainedLengthEncode(PPER_Stream & strm, unsigned length) const
{
  if (ConstraintEncode(strm, length)) // 26.4
    strm.LengthEncode(length, 0, INT_MAX);
  else
    strm.LengthEncode(length, lowerLimit, upperLimit);
}


PBoolean PASN_ConstrainedObject::ConstraintEncode(PPER_Stream & strm, unsigned value) const
{
  if (!m_extendable)
    return constraint != FixedConstraint;

  PBoolean needsExtending = value > upperLimit;

  if (!needsExtending) {
    if (lowerLimit < 0) {
      if ((int)value < lowerLimit)
        needsExtending = true;
    }
    else {
      if (value < (unsigned)lowerLimit)
        needsExtending = true;
    }
  }

  strm.SingleBitEncode(needsExtending);

  return needsExtending;
}

///////////////////////////////////////////////////////////////////////

PBoolean PPER_Stream::BooleanDecode(PASN_Boolean & value)
{
  if (IsAtEnd())
    return false;

  // X.691 Section 11
  value = (PBoolean)SingleBitDecode();
  return true;
}


void PPER_Stream::BooleanEncode(const PASN_Boolean & value)
{
  // X.691 Section 11
  SingleBitEncode((PBoolean)value);
}

PBoolean PPER_Stream::IntegerDecode(PASN_Integer & value)
{
  return value.DecodePER(*this);
}


void PPER_Stream::IntegerEncode(const PASN_Integer & value)
{
  value.EncodePER(*this);
}

///////////////////////////////////////////////////////////////////////

PBoolean PASN_Integer::DecodePER(PPER_Stream & strm)
{
  // X.691 Sections 12

  switch (constraint) {
    case FixedConstraint : // 12.2.1 & 12.2.2
      break;

    case ExtendableConstraint :
      if (!strm.SingleBitDecode()) //  12.1
        break;
      // Fall into default case for unconstrained or partially constrained

    default : // 12.2.6
      unsigned len;
      if (!strm.LengthDecode(0, INT_MAX, len))
        return false;

      len *= 8;
      if (!strm.MultiBitDecode(len, value))
        return false;

      if (IsUnsigned())
        value += lowerLimit;
      else if ((value&(1<<(len-1))) != 0) // Negative
        value |= UINT_MAX << len;         // Sign extend
      return true;
  }

  if ((unsigned)lowerLimit != upperLimit)  // 12.2.2
    return strm.UnsignedDecode(lowerLimit, upperLimit, value); // which devolves to 10.5

  // 12.2.1
  value = lowerLimit;
  return true;
}


void PASN_Integer::EncodePER(PPER_Stream & strm) const
{
  // X.691 Sections 12

  //  12.1
  if (ConstraintEncode(strm, (int)value)) {
    // 12.2.6
    unsigned adjusted_value = value - lowerLimit;

    PINDEX nBits = 1; // Allow for sign bit
    if (IsUnsigned())
      nBits = CountBits(adjusted_value+1);
    else if ((int)adjusted_value > 0)
      nBits += CountBits(adjusted_value+1);
    else
      nBits += CountBits(-(int)adjusted_value+1);

    // Round up to nearest number of whole octets
    PINDEX nBytes = (nBits+7)/8;
    strm.LengthEncode(nBytes, 0, INT_MAX);
    strm.MultiBitEncode(adjusted_value, nBytes*8);
    return;
  }

  if ((unsigned)lowerLimit == upperLimit) // 12.2.1
    return;

  // 12.2.2 which devolves to 10.5
  strm.UnsignedEncode(value, lowerLimit, upperLimit);
}

///////////////////////////////////////////////////////////////////////

PBoolean PPER_Stream::EnumerationDecode(PASN_Enumeration & value)
{
  return value.DecodePER(*this);
}


void PPER_Stream::EnumerationEncode(const PASN_Enumeration & value)
{
  value.EncodePER(*this);
}


PBoolean PASN_Enumeration::DecodePER(PPER_Stream & strm)
{
  // X.691 Section 13

  if (m_extendable) {  // 13.3
    if (strm.SingleBitDecode()) {
      unsigned len = 0;
      return strm.SmallUnsignedDecode(len) &&
             len > 0 &&
             strm.UnsignedDecode(0, len-1, value);
    }
  }

  return strm.UnsignedDecode(0, maxEnumValue, value);  // 13.2
}


void PASN_Enumeration::EncodePER(PPER_Stream & strm) const
{
  // X.691 Section 13

  if (m_extendable) {  // 13.3
    PBoolean extended = value > maxEnumValue;
    strm.SingleBitEncode(extended);
    if (extended) {
      strm.SmallUnsignedEncode(1+value);
      strm.UnsignedEncode(value, 0, value);
      return;
    }
  }

  strm.UnsignedEncode(value, 0, maxEnumValue);  // 13.2
}

///////////////////////////////////////////////////////////////////////

PBoolean PPER_Stream::RealDecode(PASN_Real &)
{
  // X.691 Section 14

  if (IsAtEnd())
    return false;

  unsigned len;
  if (!MultiBitDecode(8, len))
    return false;

  byteOffset += len+1;
  return true;
}


void PPER_Stream::RealEncode(const PASN_Real &)
{
  // X.691 Section 14

  MultiBitEncode(0, 8);
  PAssertAlways(PUnimplementedFunction);
  MultiBitEncode(0, 8);
}

///////////////////////////////////////////////////////////////////////

PBoolean PPER_Stream::ObjectIdDecode(PASN_ObjectId & value)
{
  // X.691 Section 23

  unsigned dataLen;
  if (!LengthDecode(0, 255, dataLen))
    return false;

  ByteAlign();
  return value.CommonDecode(*this, dataLen);
}


void PPER_Stream::ObjectIdEncode(const PASN_ObjectId & value)
{
  // X.691 Section 23

  PBYTEArray eObjId;
  value.CommonEncode(eObjId);
  LengthEncode(eObjId.GetSize(), 0, 255);
  BlockEncode(eObjId, eObjId.GetSize());
}

///////////////////////////////////////////////////////////////////////

PBoolean PASN_BitString::DecodeSequenceExtensionBitmap(PPER_Stream & strm)
{
  if (!strm.SmallUnsignedDecode(totalBits))
    return false;

  totalBits++;

  if (!SetSize(totalBits))
    return false;

  if (totalBits > strm.GetBitsLeft())
    return false;

  unsigned theBits;

  PINDEX idx = 0;
  unsigned bitsLeft = totalBits;
  while (bitsLeft >= 8) {
    if (!strm.MultiBitDecode(8, theBits))
      return false;
    bitData[idx++] = (BYTE)theBits;
    bitsLeft -= 8;
  }

  if (bitsLeft > 0) {
    if (!strm.MultiBitDecode(bitsLeft, theBits))
      return false;
    bitData[idx] = (BYTE)(theBits << (8-bitsLeft));
  }

  return true;
}


void PASN_BitString::EncodeSequenceExtensionBitmap(PPER_Stream & strm) const
{
  PAssert(totalBits > 0, PLogicError);

  unsigned bitsLeft = totalBits;
  while (bitsLeft > 1 && !(*this)[bitsLeft-1])
    bitsLeft--;

  strm.SmallUnsignedEncode(bitsLeft-1);

  PINDEX idx = 0;
  while (bitsLeft >= 8) {
    strm.MultiBitEncode(bitData[idx++], 8);
    bitsLeft -= 8;
  }

  if (bitsLeft > 0)
    strm.MultiBitEncode(bitData[idx] >> (8 - bitsLeft), bitsLeft);
}


PBoolean PASN_BitString::DecodePER(PPER_Stream & strm)
{
  // X.691 Section 15

  if (!ConstrainedLengthDecode(strm, totalBits))
    return false;

  if (!SetSize(totalBits))
    return false;

  if (totalBits == 0)
    return true;   // 15.7

  if (totalBits > strm.GetBitsLeft())
    return false;

  if (totalBits > 16) {
    unsigned nBytes = (totalBits+7)/8;
    return strm.BlockDecode(bitData.GetPointer(), nBytes) == nBytes;   // 15.9
  }

  unsigned theBits;
  if (totalBits <= 8) {
    if (!strm.MultiBitDecode(totalBits, theBits))
      return false;

    bitData[(PINDEX)0] = (BYTE)(theBits << (8-totalBits));
  }
  else {  // 15.8
    if (!strm.MultiBitDecode(8, theBits))
      return false;

    bitData[(PINDEX)0] = (BYTE)theBits;

    if (!strm.MultiBitDecode(totalBits-8, theBits))
      return false;

    bitData[(PINDEX)1] = (BYTE)(theBits << (16-totalBits));
  }

  return true;
}


void PASN_BitString::EncodePER(PPER_Stream & strm) const
{
  // X.691 Section 15

  ConstrainedLengthEncode(strm, totalBits);

  if (totalBits == 0)
    return;

  if (totalBits > 16)
    strm.BlockEncode(bitData, (totalBits+7)/8);   // 15.9
  else if (totalBits <= 8)  // 15.8
    strm.MultiBitEncode(bitData[(PINDEX)0] >> (8 - totalBits), totalBits);
  else {
    strm.MultiBitEncode(bitData[(PINDEX)0], 8);
    strm.MultiBitEncode(bitData[(PINDEX)1] >> (16 - totalBits), totalBits-8);
  }
}

///////////////////////////////////////////////////////////////////////

PBoolean PPER_Stream::BitStringDecode(PASN_BitString & value)
{
  return value.DecodePER(*this);
}


void PPER_Stream::BitStringEncode(const PASN_BitString & value)
{
  value.EncodePER(*this);
}

///////////////////////////////////////////////////////////////////////

PBoolean PASN_OctetString::DecodeSubType(PASN_Object & obj) const
{
  PPER_Stream stream = GetValue();
  return obj.Decode(stream);
}


void PASN_OctetString::EncodeSubType(const PASN_Object & obj)
{
  PPER_Stream stream;
  obj.Encode(stream);
  stream.CompleteEncoding();
  SetValue(stream);
}

PBoolean PASN_OctetString::DecodePER(PPER_Stream & strm)
{
  // X.691 Section 16

  unsigned nBytes;
  if (!ConstrainedLengthDecode(strm, nBytes))
    return false;

  if (!SetSize(nBytes))   // 16.5
    return false;

  if ((int)upperLimit != lowerLimit)
    return strm.BlockDecode(value.GetPointer(), nBytes) == nBytes;

  unsigned theBits;
  switch (nBytes) {
    case 0 :
      break;

    case 1 :  // 16.6
      if (!strm.MultiBitDecode(8, theBits))
        return false;
      value[(PINDEX)0] = (BYTE)theBits;
      break;

    case 2 :  // 16.6
      if (!strm.MultiBitDecode(8, theBits))
        return false;
      value[(PINDEX)0] = (BYTE)theBits;
      if (!strm.MultiBitDecode(8, theBits))
        return false;
      value[(PINDEX)1] = (BYTE)theBits;
      break;

    default: // 16.7
      return strm.BlockDecode(value.GetPointer(), nBytes) == nBytes;
  }

  return true;
}


void PASN_OctetString::EncodePER(PPER_Stream & strm) const
{
  // X.691 Section 16

  PINDEX nBytes = value.GetSize();
  ConstrainedLengthEncode(strm, nBytes);

  if ((int)upperLimit != lowerLimit) {
    strm.BlockEncode(value, nBytes);
    return;
  }

  switch (nBytes) {
    case 0 :  // 16.5
      break;

    case 1 :  // 16.6
      strm.MultiBitEncode(value[(PINDEX)0], 8);
      break;

    case 2 :  // 16.6
      strm.MultiBitEncode(value[(PINDEX)0], 8);
      strm.MultiBitEncode(value[(PINDEX)1], 8);
      break;

    default: // 16.7
      strm.BlockEncode(value, nBytes);
  }
}

PBoolean PPER_Stream::OctetStringDecode(PASN_OctetString & value)
{
  return value.DecodePER(*this);
}


void PPER_Stream::OctetStringEncode(const PASN_OctetString & value)
{
  value.EncodePER(*this);
}

///////////////////////////////////////////////////////////////////////

PBoolean PASN_ConstrainedString::DecodePER(PPER_Stream & strm)
{
  // X.691 Section 26

  unsigned len;
  if (!ConstrainedLengthDecode(strm, len))
    return false;

  if (len == 0) { // 10.9.3.3
    value.SetSize(1);
    value[(PINDEX)0] = '\0';
    return true;
  }

  unsigned nBits = strm.IsAligned() ? charSetAlignedBits : charSetUnalignedBits;
  unsigned totalBits = upperLimit*nBits;

  if (constraint == Unconstrained ||
            (lowerLimit == (int)upperLimit ? (totalBits > 16) : (totalBits >= 16))) {
    if (nBits == 8)
      return strm.BlockDecode((BYTE *)value.GetPointerAndSetLength(len), len) == len;
    if (strm.IsAligned())
      strm.ByteAlign();
  }

  if ((PINDEX)len > MaximumStringSize)
    return false;

  char * valuePtr = value.GetPointerAndSetLength(len);
  if (valuePtr == NULL)
    return false;

  for (unsigned i = 0; i < len; i++, valuePtr++) {
    unsigned theBits;
    if (!strm.MultiBitDecode(nBits, theBits))
      return false;
    if (nBits >= canonicalSetBits && canonicalSetBits > 4)
      *valuePtr = (char)theBits;
    else
      *valuePtr = characterSet[(PINDEX)theBits];
  }
  *valuePtr = '\0';

  return true;
}


void PASN_ConstrainedString::EncodePER(PPER_Stream & strm) const
{
  // X.691 Section 26

  PINDEX len = value.GetSize()-1;
  ConstrainedLengthEncode(strm, len);

  if (len == 0) // 10.9.3.3
    return;

  unsigned nBits = strm.IsAligned() ? charSetAlignedBits : charSetUnalignedBits;
  unsigned totalBits = upperLimit*nBits;

  if (constraint == Unconstrained ||
            (lowerLimit == (int)upperLimit ? (totalBits > 16) : (totalBits >= 16))) {
    // 26.5.7
    if (nBits == 8) {
      strm.BlockEncode((const BYTE *)(const char *)value, len);
      return;
    }
    if (strm.IsAligned())
      strm.ByteAlign();
  }

  for (PINDEX i = 0; i < len; i++) {
    if (nBits >= canonicalSetBits && canonicalSetBits > 4)
      strm.MultiBitEncode(value[i], nBits);
    else {
      const void * ptr = memchr(characterSet, value[i], characterSet.GetSize());
      PINDEX pos = 0;
      if (ptr != NULL)
        pos = ((const char *)ptr - (const char *)characterSet);
      strm.MultiBitEncode(pos, nBits);
    }
  }
}

///////////////////////////////////////////////////////////////////////

PBoolean PPER_Stream::ConstrainedStringDecode(PASN_ConstrainedString & value)
{
  return value.DecodePER(*this);
}


void PPER_Stream::ConstrainedStringEncode(const PASN_ConstrainedString & value)
{
  value.EncodePER(*this);
}

///////////////////////////////////////////////////////////////////////

PBoolean PASN_BMPString::DecodePER(PPER_Stream & strm)
{
  // X.691 Section 26

  unsigned len;
  if (!ConstrainedLengthDecode(strm, len))
    return false;

  if ((PINDEX)len > MaximumStringSize)
    return false;

  if (!value.SetSize(len))
    return false;

  PINDEX nBits = strm.IsAligned() ? charSetAlignedBits : charSetUnalignedBits;

  if ((constraint == Unconstrained || upperLimit*nBits > 16) && strm.IsAligned())
    strm.ByteAlign();

  for (PINDEX i = 0; i < (PINDEX)len; i++) {
    unsigned theBits;
    if (!strm.MultiBitDecode(nBits, theBits))
      return false;
    if (characterSet.IsEmpty())
      value[i] = (WORD)(theBits + firstChar);
    else
      value[i] = characterSet[(PINDEX)theBits];
  }

  return true;
}


void PASN_BMPString::EncodePER(PPER_Stream & strm) const
{
  // X.691 Section 26

  PINDEX len = value.GetSize();
  ConstrainedLengthEncode(strm, len);

  PINDEX nBits = strm.IsAligned() ? charSetAlignedBits : charSetUnalignedBits;

  if ((constraint == Unconstrained || upperLimit*nBits > 16) && strm.IsAligned())
    strm.ByteAlign();

  for (PINDEX i = 0; i < len; i++) {
    if (characterSet.IsEmpty())
      strm.MultiBitEncode(value[i] - firstChar, nBits);
    else {
      for (PINDEX pos = 0; pos < characterSet.GetSize(); pos++) {
        if (characterSet[pos] == value[i]) {
          strm.MultiBitEncode(pos, nBits);
          break;
        }
      }
    }
  }
}


PBoolean PPER_Stream::BMPStringDecode(PASN_BMPString & value)
{
  return value.DecodePER(*this);
}


void PPER_Stream::BMPStringEncode(const PASN_BMPString & value)
{
  value.EncodePER(*this);
}

///////////////////////////////////////////////////////////////////////

PBoolean PASN_Choice::DecodePER(PPER_Stream & strm)
{
  // X.691 Section 22
  delete choice;
  choice = NULL;

  if (strm.IsAtEnd())
    return false;

  if (m_extendable) {
    if (strm.SingleBitDecode()) {
      if (!strm.SmallUnsignedDecode(m_tag))
        return false;

      m_tag += numChoices;

      unsigned len = 0;
      if (!strm.LengthDecode(0, INT_MAX, len))
        return false;

      PBoolean ok;
      if (CreateObject()) {
        PINDEX nextPos = strm.GetPosition() + len;
        ok = choice->Decode(strm);
        strm.SetPosition(nextPos);
      }
      else {
        PASN_OctetString * open_type = new PASN_OctetString;
        open_type->SetConstraints(PASN_ConstrainedObject::FixedConstraint, len);
        ok = open_type->Decode(strm);
        if (open_type->GetSize() > 0)
          choice = open_type;
        else {
          delete open_type;
          ok = false;
        }
      }
      return ok;
    }
  }

  if (numChoices < 2)
    m_tag = 0;
  else {
    if (!strm.UnsignedDecode(0, numChoices-1, m_tag))
      return false;
  }

  return CreateObject() && choice && choice->Decode(strm);
}


void PASN_Choice::EncodePER(PPER_Stream & strm) const
{
  PAssert(CheckCreate(), PLogicError);

  if (m_extendable) {
    PBoolean extended = m_tag >= numChoices;
    strm.SingleBitEncode(extended);
    if (extended) {
      strm.SmallUnsignedEncode(m_tag - numChoices);
      strm.AnyTypeEncode(choice);
      return;
    }
  }

  if (numChoices > 1)
    strm.UnsignedEncode(m_tag, 0, numChoices-1);

  choice->Encode(strm);
}


PBoolean PPER_Stream::ChoiceDecode(PASN_Choice & value)
{
  return value.DecodePER(*this);
}


void PPER_Stream::ChoiceEncode(const PASN_Choice & value)
{
  value.EncodePER(*this);
}

///////////////////////////////////////////////////////////////////////

PBoolean PASN_Sequence::PreambleDecodePER(PPER_Stream & strm)
{
  // X.691 Section 18

  totalExtensions = 0;
  extensionMap.SetSize(0);

  if (m_extendable) {
    if (strm.IsAtEnd())
      return false;
    if (strm.SingleBitDecode()) // 18.1
      totalExtensions = -1;
  }

  return optionMap.Decode(strm);  // 18.2
}


void PASN_Sequence::PreambleEncodePER(PPER_Stream & strm) const
{
  // X.691 Section 18

  if (m_extendable) {
    PBoolean hasExtensions = false;
    for (unsigned i = 0; i < extensionMap.GetSize(); i++) {
      if (extensionMap[i]) {
        hasExtensions = true;
        break;
      }
    }
    strm.SingleBitEncode(hasExtensions);  // 18.1
    ((PASN_Sequence*)this)->totalExtensions = hasExtensions ? -1 : 0;
  }
  optionMap.Encode(strm);  // 18.2
}


PBoolean PASN_Sequence::NoExtensionsToDecode(PPER_Stream & strm)
{
  if (totalExtensions == 0)
    return true;

  if (totalExtensions < 0) {
    if (!extensionMap.DecodeSequenceExtensionBitmap(strm))
      return false;
    totalExtensions = extensionMap.GetSize();
  }

  return false;
}


PBoolean PASN_Sequence::NoExtensionsToEncode(PPER_Stream & strm)
{
  if (totalExtensions == 0)
    return true;

  if (totalExtensions < 0) {
    totalExtensions = extensionMap.GetSize();
    extensionMap.EncodeSequenceExtensionBitmap(strm);
  }

  return false;
}


PBoolean PASN_Sequence::KnownExtensionDecodePER(PPER_Stream & strm, PINDEX fld, PASN_Object & field)
{
  if (NoExtensionsToDecode(strm))
    return true;

  if (!extensionMap[fld-optionMap.GetSize()])
    return true;

  unsigned len;
  if (!strm.LengthDecode(0, INT_MAX, len))
    return false;

  PINDEX nextExtensionPosition = strm.GetPosition() + len;
  PBoolean ok = field.Decode(strm);
  strm.SetPosition(nextExtensionPosition);
  return ok;
}


void PASN_Sequence::KnownExtensionEncodePER(PPER_Stream & strm, PINDEX fld, const PASN_Object & field) const
{
  if (((PASN_Sequence*)this)->NoExtensionsToEncode(strm))
    return;

  if (!extensionMap[fld-optionMap.GetSize()])
    return;

  strm.AnyTypeEncode(&field);
}


PBoolean PASN_Sequence::UnknownExtensionsDecodePER(PPER_Stream & strm)
{
  if (NoExtensionsToDecode(strm))
    return true;

  if (totalExtensions <= knownExtensions)
    return true;  // Already read them

  PINDEX unknownCount = totalExtensions - knownExtensions;
  if (fields.GetSize() >= unknownCount)
    return true;  // Already read them

  if (unknownCount > MaximumArraySize)
    return false;

  if (!fields.SetSize(unknownCount))
    return false;

  PINDEX i;
  for (i = 0; i < fields.GetSize(); i++)
    fields.SetAt(i, new PASN_OctetString);

  for (i = knownExtensions; i < (PINDEX)extensionMap.GetSize(); i++) {
    if (extensionMap[i])
      if (!fields[i-knownExtensions].Decode(strm))
        return false;
  }

  return true;
}


void PASN_Sequence::UnknownExtensionsEncodePER(PPER_Stream & strm) const
{
  if (((PASN_Sequence*)this)->NoExtensionsToEncode(strm))
    return;

  int i;
  for (i = knownExtensions; i < totalExtensions; i++) {
    if (extensionMap[i]) {
      PINDEX f = i - knownExtensions;
      if (f < fields.GetSize())
        fields[f].Encode(strm);
      else {
        PASN_OctetString dummy;
        dummy.Encode(strm);
      }
    }
  }
}


PBoolean PPER_Stream::SequencePreambleDecode(PASN_Sequence & seq)
{
  return seq.PreambleDecodePER(*this);
}


void PPER_Stream::SequencePreambleEncode(const PASN_Sequence & seq)
{
  seq.PreambleEncodePER(*this);
}


PBoolean PPER_Stream::SequenceKnownDecode(PASN_Sequence & seq, PINDEX fld, PASN_Object & field)
{
  return seq.KnownExtensionDecodePER(*this, fld, field);
}


void PPER_Stream::SequenceKnownEncode(const PASN_Sequence & seq, PINDEX fld, const PASN_Object & field)
{
  seq.KnownExtensionEncodePER(*this, fld, field);
}


PBoolean PPER_Stream::SequenceUnknownDecode(PASN_Sequence & seq)
{
  return seq.UnknownExtensionsDecodePER(*this);
}


void PPER_Stream::SequenceUnknownEncode(const PASN_Sequence & seq)
{
  seq.UnknownExtensionsEncodePER(*this);
}

///////////////////////////////////////////////////////////////////////

PBoolean PPER_Stream::ArrayDecode(PASN_Array & array)
{
  array.RemoveAll();

  unsigned size = 0;
  if (!array.ConstrainedLengthDecode(*this, size))
    return false;

  if (!array.SetSize(size))
    return false;

  for (PINDEX i = 0; i < (PINDEX)size; i++) {
    if (!array[i].Decode(*this))
      return false;
  }

  return true;
}


void PPER_Stream::ArrayEncode(const PASN_Array & array)
{
  PINDEX size = array.GetSize();
  array.ConstrainedLengthEncode(*this, size);
  for (PINDEX i = 0; i < size; i++)
    array[i].Encode(*this);
}

///////////////////////////////////////////////////////////////////////

PPER_Stream::PPER_Stream(int alignment)
{
  aligned = alignment;
}


PPER_Stream::PPER_Stream(const PBYTEArray & bytes, PBoolean alignment)
  : PASN_Stream(bytes)
{
  aligned = alignment;
}


PPER_Stream::PPER_Stream(const BYTE * buf, PINDEX size, PBoolean alignment)
  : PASN_Stream(buf, size)
{
  aligned = alignment;
}


PPER_Stream & PPER_Stream::operator=(const PBYTEArray & bytes)
{
  PBYTEArray::operator=(bytes);
  ResetDecoder();
  aligned = true;
  return *this;
}


unsigned PPER_Stream::GetBitsLeft() const
{
  return (GetSize() - byteOffset)*8 - (8 - bitOffset);
}


PBoolean PPER_Stream::Read(PChannel & chan)
{
  ResetDecoder();
  SetSize(0);

  // Get RFC1006 TPKT length
  BYTE tpkt[4];
  if (!chan.ReadBlock(tpkt, sizeof(tpkt)))
    return false;

  if (tpkt[0] != 3) // Only support version 3
    return true;

  PINDEX data_len = ((tpkt[2] << 8)|tpkt[3]) - 4;

  return chan.ReadBlock(GetPointer(data_len), data_len);
}


PBoolean PPER_Stream::Write(PChannel & chan)
{
  CompleteEncoding();

  PINDEX size = GetSize();

  // Put RFC1006 TPKT length
  BYTE tpkt[4];
  tpkt[0] = 3;  // Version 3
  tpkt[1] = 0;

  PINDEX len = size + sizeof(tpkt);
  tpkt[2] = (BYTE)(len >> 8);
  tpkt[3] = (BYTE)len;

  return chan.Write(tpkt, sizeof(tpkt)) && chan.Write(theArray, size);
}


PBoolean PPER_Stream::SingleBitDecode()
{
  if (!CheckByteOffset(byteOffset) || ((GetSize() - byteOffset)*8 - (8 - bitOffset) == 0))
    return false;

  bitOffset--;

  PBoolean value = (theArray[byteOffset] & (1 << bitOffset)) != 0;

  if (bitOffset == 0) {
    bitOffset = 8;
    byteOffset++;
  }

  return value;
}


void PPER_Stream::SingleBitEncode(PBoolean value)
{
  if (!CheckByteOffset(byteOffset))
    return;

  if (byteOffset >= GetSize())
    SetSize(byteOffset+10);

  bitOffset--;

  if (value)
    theArray[byteOffset] |= 1 << bitOffset;

  if (bitOffset == 0)
    ByteAlign();
}


PBoolean PPER_Stream::MultiBitDecode(unsigned nBits, unsigned & value)
{
  if (nBits > sizeof(value)*8)
    return false;

  unsigned bitsLeft = (GetSize() - byteOffset)*8 - (8 - bitOffset);
  if (nBits > bitsLeft)
    return false;

  if (nBits == 0) {
    value = 0;
    return true;
  }

  if (!CheckByteOffset(byteOffset))
    return false;

  if (nBits < bitOffset) {
    bitOffset -= nBits;
    value = (theArray[byteOffset] >> bitOffset) & ((1 << nBits) - 1);
    return true;
  }

  value = theArray[byteOffset] & ((1 << bitOffset) - 1);
  nBits -= bitOffset;
  bitOffset = 8;
  byteOffset++;

  while (nBits >= 8) {
    value = (value << 8) | (BYTE)theArray[byteOffset];
    byteOffset++;
    nBits -= 8;
  }

  if (nBits > 0) {
    bitOffset = 8 - nBits;
    value = (value << nBits) | ((BYTE)theArray[byteOffset] >> bitOffset);
  }

  return true;
}


void PPER_Stream::MultiBitEncode(unsigned value, unsigned nBits)
{
  PAssert(byteOffset != P_MAX_INDEX, PLogicError);

  if (nBits == 0 || !PAssert(!((nBits < sizeof(value)*8) && (value > (value & ((1 << nBits) - 1)))), PInvalidParameter))
    return;

  if (byteOffset+nBits/8+1 >= (unsigned)GetSize())
    SetSize(byteOffset+10);

  // Make sure value is in bounds of bit available.
  if (nBits < sizeof(value)*8)
    value &= ((1 << nBits) - 1);

  if (!CheckByteOffset(byteOffset))
    return;

  if (nBits < bitOffset) {
    bitOffset -= nBits;
    theArray[byteOffset] |= value << bitOffset;
    return;
  }

  nBits -= bitOffset;
  theArray[byteOffset] |= (BYTE)(value >> nBits);
  bitOffset = 8;
  byteOffset++;

  while (nBits >= 8) {
    nBits -= 8;
    theArray[byteOffset] = (BYTE)(value >> nBits);
    byteOffset++;
  }

  if (nBits > 0) {
    bitOffset = 8 - nBits;
    theArray[byteOffset] |= (BYTE)((value & ((1 << nBits)-1)) << bitOffset);
  }
}


PBoolean PPER_Stream::SmallUnsignedDecode(unsigned & value)
{
  // X.691 Section 10.6

  if (!SingleBitDecode())
    return MultiBitDecode(6, value);      // 10.6.1

  unsigned len = 0;
  if (!LengthDecode(0, INT_MAX, len))  // 10.6.2
    return false;

  ByteAlign();
  return MultiBitDecode(len*8, value);
}


void PPER_Stream::SmallUnsignedEncode(unsigned value)
{
  if (value < 64) {
    MultiBitEncode(value, 7);
    return;
  }

  SingleBitEncode(1);  // 10.6.2

  PINDEX len = 4;
  if (value < 256)
    len = 1;
  else if (value < 65536)
    len = 2;
  else if (value < 0x1000000)
    len = 3;
  LengthEncode(len, 0, INT_MAX);  // 10.9
  ByteAlign();
  MultiBitEncode(value, len*8);
}


PBoolean PPER_Stream::UnsignedDecode(unsigned lower, unsigned upper, unsigned & value)
{
  // X.691 section 10.5

  if (lower == upper) { // 10.5.4
    value = lower;
    return true;
  }

  if (IsAtEnd())
    return false;

  unsigned range = (upper - lower) + 1;
  unsigned nBits = CountBits(range);

  if (aligned && (range == 0 || range > 255)) { // not 10.5.6 and not 10.5.7.1
    if (nBits > 16) {                           // not 10.5.7.4
      if (!LengthDecode(1, (nBits+7)/8, nBits))      // 12.2.6
        return false;
      nBits *= 8;
    }
    else if (nBits > 8)    // not 10.5.7.2
      nBits = 16;          // 10.5.7.3
    ByteAlign();           // 10.7.5.2 - 10.7.5.4
  }

  if (!MultiBitDecode(nBits, value))
    return false;

  value += lower;

  // clamp value to upper limit
  if (value > upper)
    value = upper;

  return true;
}


void PPER_Stream::UnsignedEncode(int value, unsigned lower, unsigned upper)
{
  // X.691 section 10.5

  if (lower == upper) // 10.5.4
    return;

  unsigned range = (upper - lower) + 1;
  PINDEX nBits = CountBits(range);

  if ((unsigned)value < lower)
    value = 0;
  else
    value -= lower;

  if (aligned && (range == 0 || range > 255)) { // not 10.5.6 and not 10.5.7.1
    if (nBits > 16) {                           // not 10.5.7.4
      int numBytes = value == 0 ? 1 : (((CountBits(value + 1))+7)/8);
      LengthEncode(numBytes, 1, (nBits+7)/8);    // 12.2.6
      nBits = numBytes*8;
    }
    else if (nBits > 8)      // not 10.5.7.2
      nBits = 16;            // 10.5.7.3
    ByteAlign();             // 10.7.5.2 - 10.7.5.4
  }

  MultiBitEncode(value, nBits);
}


PBoolean PPER_Stream::LengthDecode(unsigned lower, unsigned upper, unsigned & len)
{
  // X.691 section 10.9

  if (upper != INT_MAX && !aligned) {
    if (upper - lower > 0xffff)
      return false; // 10.9.4.2 unsupported
    unsigned base;
    if (!MultiBitDecode(CountBits(upper - lower + 1), base))
      return false;
    len = lower + base;   // 10.9.4.1

    // clamp value to upper limit
    if (len > upper)
      len = upper;

    return true;
  }

  if (upper < 65536)  // 10.9.3.3
    return UnsignedDecode(lower, upper, len);

  // 10.9.3.5
  ByteAlign();
  if (IsAtEnd())
    return false;

  if (SingleBitDecode() == 0) {
    if (!MultiBitDecode(7, len))   // 10.9.3.6
      return false;                // 10.9.3.8 unsupported
  }

  else if (SingleBitDecode() == 0) {
    if (!MultiBitDecode(14, len))    // 10.9.3.7
      return false;                  // 10.9.3.8 unsupported
  }

  // clamp value to upper limit
  if (len > upper)
    len = upper;

  return true;  
}


void PPER_Stream::LengthEncode(unsigned len, unsigned lower, unsigned upper)
{
  // X.691 section 10.9

  if (upper != INT_MAX && !aligned) {
    PAssert(upper - lower < 0x10000, PUnimplementedFunction);  // 10.9.4.2 unsupperted
    MultiBitEncode(len - lower, CountBits(upper - lower + 1));   // 10.9.4.1
    return;
  }

  if (upper < 65536) { // 10.9.3.3
    UnsignedEncode(len, lower, upper);
    return;
  }

  ByteAlign();

  if (len < 128) {
    MultiBitEncode(len, 8);   // 10.9.3.6
    return;
  }

  SingleBitEncode(true);

  if (len < 0x4000) {
    MultiBitEncode(len, 15);    // 10.9.3.7
    return;
  }

  SingleBitEncode(true);
  PAssertAlways(PUnimplementedFunction);  // 10.9.3.8 unsupported
}


void PPER_Stream::AnyTypeEncode(const PASN_Object * value)
{
  PPER_Stream substream;

  if (value != NULL)
    value->Encode(substream);

  substream.CompleteEncoding();

  PINDEX nBytes = substream.GetSize();
  if (nBytes == 0) {
    const BYTE null[1] = { 0 };
    nBytes = sizeof(null);
    substream = PBYTEArray(null, nBytes, false);
  }

  LengthEncode(nBytes, 0, INT_MAX);
  BlockEncode(substream.GetPointer(), nBytes);
}

///////////////////////////////////////////////////////////////////////
