/*
 * videoio.cxx
 *
 * Classes to support streaming video input (grabbing) and output.
 *
 * Portable Windows Library
 *
 * Copyright (c) 1993-2000 Equivalence Pty. Ltd.
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
 * Contributor(s): Mark Cooke (mpc@star.sr.bham.ac.uk)
 */

#ifdef __GNUC__
#pragma implementation "videoio.h"
#endif 

#include <ptlib.h>

#if P_VIDEO

#include <ptlib/pluginmgr.h>
#include <ptlib/videoio.h>
#include <ptlib/vconvert.h>


#define PTraceModule() "PVidDev"


///////////////////////////////////////////////////////////////////////////////

const PString & PVideoFrameInfo::YUV420P() { static PConstString const s(PTLIB_VIDEO_YUV420P); return s; }

static PINDEX CalculateFrameBytesYUV420(unsigned width, unsigned height)
{
  // Cannot have odd dimensions due to UV resolution reduction
  return ((width+1)&~1) * ((height+1)&~1) * 3 / 2;
}

static PINDEX CalculateFrameBytesRGB24(unsigned width, unsigned height)
{
  return ((width*3+3)&~3) * height;
}

//Colour format bit per pixel table.
// These are in rough order of colour gamut size and "popularity"
static struct {
  const char * colourFormat;
  unsigned     bitsPerPixel;
  PINDEX (*calculate)(unsigned width, unsigned height);
  const char * synonym;

  PINDEX CalculateFrameBytes(unsigned width, unsigned height)
  {
      if (calculate)
          return calculate(width, height);
      return  (width * bitsPerPixel / 8) * height;
  }
} ColourFormatBPPTab[] = {
  { PTLIB_VIDEO_YUV420P, 12, CalculateFrameBytesYUV420 },
  { "I420",              12, CalculateFrameBytesYUV420, PTLIB_VIDEO_YUV420P },
  { "IYUV",              12, CalculateFrameBytesYUV420, PTLIB_VIDEO_YUV420P },
  { "YUV420",            12 },
  { "RGB32",             32 },
  { "BGR32",             32 },
  { "RGB24",             24, CalculateFrameBytesRGB24 },
  { "BGR24",             24, CalculateFrameBytesRGB24 },
  { "YUV420B",           12, CalculateFrameBytesYUV420 },
  { "NV12",              12, CalculateFrameBytesYUV420, "YUV420B" },
  { "420v",              12, CalculateFrameBytesYUV420, "YUV420B" },
  { "YUY2",              16 },
  { "YUV422",            16 },
  { "YUV422P",           16 },
  { "YUV411",            12 },
  { "YUV411P",           12 },
  { "RGB565",            16 },
  { "RGB555",            16 },
  { "RGB16",             16 },
  { "YUV410",            10 },
  { "YUV410P",           10 },
  { "Grey",               8 },
  { "GreyF",              8 },
  { "UYVY422",           16 },
  { "UYV444",            24 },
  { "SBGGR8",             8 },
  { "JPEG",              24 },
  { "MJPEG",              8 }
};


template <class VideoDevice>
static VideoDevice * CreateDeviceWithDefaults(PString & adjustedDeviceName,
                                              const PString & driverName,
                                              PPluginManager * pluginMgr)
{
  if (adjustedDeviceName == "*")
    adjustedDeviceName.MakeEmpty();

  PString adjustedDriverName = driverName;
  if (adjustedDriverName == "*")
    adjustedDriverName.MakeEmpty();

  if (adjustedDeviceName.IsEmpty()) {
    PStringArray devices = VideoDevice::GetDriversDeviceNames(adjustedDriverName);
    PTRACE(4, "Available video devices for driver \"" << adjustedDriverName << "\": " << setfill(',') << devices);
    if (devices.IsEmpty())
      return NULL;

    adjustedDeviceName = devices[0];
  }
  else if (adjustedDriverName.IsEmpty() && adjustedDeviceName.Find(PPluginServiceDescriptor::SeparatorChar) != P_MAX_INDEX) {
    adjustedDeviceName.Split(PPluginServiceDescriptor::SeparatorChar, adjustedDriverName, adjustedDeviceName);
  }

  return VideoDevice::CreateDeviceByName(adjustedDeviceName, adjustedDriverName, pluginMgr);
}


///////////////////////////////////////////////////////////////////////////////
// PVideoDevice

ostream & operator<<(ostream & strm, PVideoFrameInfo::ResizeMode mode)
{
  switch (mode) {
    case PVideoFrameInfo::eScale :
      return strm << "Scaled";
    case PVideoFrameInfo::eCropCentre :
      return strm << "Centred";
    case PVideoFrameInfo::eCropTopLeft :
      return strm << "Cropped";
    case PVideoFrameInfo::eScaleKeepAspect :
      return strm << "Aspect";
    default :
      return strm << "ResizeMode<" << (int)mode << '>';
  }
}


PVideoFrameInfo::PVideoFrameInfo()
  : m_frameWidth(CIFWidth)
  , m_frameHeight(CIFHeight)
  , m_sarWidth(1)
  , m_sarHeight(1)
  , m_frameRate(25)
  , m_colourFormat(PVideoFrameInfo::YUV420P())
  , m_resizeMode(eScale)
{
}


PVideoFrameInfo::PVideoFrameInfo(unsigned        width,
                                 unsigned        height,
                                 const PString & format,
                                 unsigned        rate,
                                 ResizeMode      resize)
  : m_frameWidth(width)
  , m_frameHeight(height)
  , m_sarWidth(1)
  , m_sarHeight(1)
  , m_frameRate(rate)
  , m_colourFormat(format)
  , m_resizeMode(resize)
{
}


PObject::Comparison PVideoFrameInfo::Compare(const PObject & obj) const
{
  const PVideoFrameInfo & other = dynamic_cast<const PVideoFrameInfo &>(obj);

  unsigned area = m_frameWidth*m_frameHeight;
  unsigned otherArea = other.m_frameWidth*other.m_frameHeight;
  if (area < otherArea)
    return LessThan;
  if (area > otherArea)
    return GreaterThan;

  if (m_frameRate < other.m_frameRate)
    return LessThan;
  if (m_frameRate > other.m_frameRate)
    return GreaterThan;

  return m_colourFormat.Compare(other.m_colourFormat);
}


void PVideoFrameInfo::PrintOn(ostream & strm) const
{
  if (!m_colourFormat.IsEmpty())
    strm << m_colourFormat << ':';

  strm << AsString(m_frameWidth, m_frameHeight);

  if (m_frameRate > 0)
    strm << '@' << m_frameRate;

  if (m_resizeMode < eMaxResizeMode)
    strm << '/' << m_resizeMode;
}


PBoolean PVideoFrameInfo::SetFrameSize(unsigned width, unsigned height)
{
  if (!PAssert(width >= 1 && height >= 1 && width < 65536 && height < 65536, PInvalidParameter))
    return false;

  m_frameWidth = width;
  m_frameHeight = height;
  return true;
}


PBoolean PVideoFrameInfo::GetFrameSize(unsigned & width, unsigned & height) const
{
  width = m_frameWidth;
  height = m_frameHeight;
  return true;
}


unsigned PVideoFrameInfo::GetFrameWidth() const
{
  unsigned w,h;
  GetFrameSize(w, h);
  return w;
}


unsigned PVideoFrameInfo::GetFrameHeight() const
{
  unsigned w,h;
  GetFrameSize(w, h);
  return h;
}


PBoolean PVideoFrameInfo::SetFrameSar(unsigned width, unsigned height)
{
  if (!PAssert(width < 65536 && height < 65536, PInvalidParameter))
    return false;

  m_sarWidth  = width;
  m_sarHeight = height;
  return true;
}


PBoolean PVideoFrameInfo::GetSarSize(unsigned & width, unsigned & height) const
{
  width  = m_sarWidth;
  height = m_sarHeight;
  return true;
}

unsigned PVideoFrameInfo::GetSarWidth() const
{
  unsigned w,h;
  GetSarSize(w, h);
  return w;
}


unsigned PVideoFrameInfo::GetSarHeight() const
{
  unsigned w,h;
  GetSarSize(w, h);
  return h;
}

PBoolean PVideoFrameInfo::SetFrameRate(unsigned rate)
{
  if (!PAssert(rate > 0 && rate < 1000, PInvalidParameter))
    return false;

  m_frameRate = rate;
  return true;
}


unsigned PVideoFrameInfo::GetFrameRate() const
{
  return m_frameRate;
}


PBoolean PVideoFrameInfo::SetColourFormat(const PString & colourFmt)
{
  if (!colourFmt.IsEmpty()) {
    // Check for synonyms
    for (PINDEX i = 0; i < PARRAYSIZE(ColourFormatBPPTab); i++) {
      if (ColourFormatBPPTab[i].synonym != NULL && colourFmt == ColourFormatBPPTab[i].colourFormat) {
        m_colourFormat = ColourFormatBPPTab[i].synonym;
        return true;
      }
    }
  
    m_colourFormat = colourFmt.ToUpper();
    return true;
  }

  for (PINDEX i = 0; i < PARRAYSIZE(ColourFormatBPPTab); i++) {
    if (SetColourFormat(ColourFormatBPPTab[i].colourFormat) ||
          (ColourFormatBPPTab[i].synonym != NULL && SetColourFormat(ColourFormatBPPTab[i].synonym)))
      return true;
  }

  return false;
}


PString PVideoFrameInfo::GetColourFormat() const
{
  return m_colourFormat;
}


PINDEX PVideoFrameInfo::CalculateFrameBytes(unsigned width, unsigned height,
                                              const PString & colourFormat)
{
  for (PINDEX i = 0; i < PARRAYSIZE(ColourFormatBPPTab); i++) {
    if (colourFormat *= ColourFormatBPPTab[i].colourFormat)
      return ColourFormatBPPTab[i].CalculateFrameBytes(width, height);
  }
  return 0;
}
 

bool PVideoFrameInfo::Parse(const PString & str)
{
  PString newFormat = m_colourFormat;
  PINDEX formatOffset = str.Find(':');
  if (formatOffset == 0)
    return false;

  if (formatOffset == P_MAX_INDEX)
    formatOffset = 0;
  else
    newFormat = str.Left(formatOffset++);


  ResizeMode newMode = m_resizeMode;
  PINDEX resizeOffset = str.Find('/', formatOffset);
  if (resizeOffset != P_MAX_INDEX) {
    static struct {
      const char * name;
      ResizeMode   mode;
    } const ResizeNames[] = {
      { "scale",   eScale },
      { "resize",  eScale },
      { "scaled",  eScale },
      { "centre",  eCropCentre },
      { "centred", eCropCentre },
      { "center",  eCropCentre },
      { "centered",eCropCentre },
      { "crop",    eCropTopLeft },
      { "cropped", eCropTopLeft },
      { "topleft", eCropTopLeft },
      { "scalekeepaspect", eScaleKeepAspect },
      { "keepaspect", eScaleKeepAspect },
      { "aspect",  eScaleKeepAspect },
    };

    PCaselessString crop = str.Mid(resizeOffset+1);
    PINDEX resizeIndex = 0;
    while (crop != ResizeNames[resizeIndex].name) {
      if (++resizeIndex >= PARRAYSIZE(ResizeNames))
        return false;
    }
    newMode = ResizeNames[resizeIndex].mode;
  }


  int newRate = m_frameRate;
  PINDEX rateOffset = str.Find('@', formatOffset);
  if (rateOffset == P_MAX_INDEX)
    rateOffset = resizeOffset;
  else {
    newRate = str.Mid(rateOffset+1).AsInteger();
    if (newRate < 1 || newRate > 100)
      return false;
  }

  if (!ParseSize(str(formatOffset, rateOffset-1), m_frameWidth, m_frameHeight))
    return false;

  m_colourFormat = newFormat;
  m_frameRate = newRate;
  m_resizeMode = newMode;
  return true;
}


static struct {
  const char * name;
  unsigned width;
  unsigned height;
} const SizeTable[] = {
    { "CIF",    PVideoDevice::CIFWidth,   PVideoDevice::CIFHeight   },
    { "QCIF",   PVideoDevice::QCIFWidth,  PVideoDevice::QCIFHeight  },
    { "SQCIF",  PVideoDevice::SQCIFWidth, PVideoDevice::SQCIFHeight },
    { "CIF4",   PVideoDevice::CIF4Width,  PVideoDevice::CIF4Height  },
    { "4CIF",   PVideoDevice::CIF4Width,  PVideoDevice::CIF4Height  },
    { "CIF16",  PVideoDevice::CIF16Width, PVideoDevice::CIF16Height },
    { "16CIF",  PVideoDevice::CIF16Width, PVideoDevice::CIF16Height },

    { "CCIR601",720,                      486                       },
    { "NTSC",   720,                      480                       },
    { "PAL",    768,                      576                       },
    { "HD480",  PVideoDevice::HD480Width, PVideoDevice::HD480Height },
    { "HD720",  PVideoDevice::HD720Width, PVideoDevice::HD720Height },
    { "HDTVP",  PVideoDevice::HD720Width, PVideoDevice::HD720Height },
    { "720p",   PVideoDevice::HD720Width, PVideoDevice::HD720Height },
    { "HD1080", PVideoDevice::HD1080Width,PVideoDevice::HD1080Height},
    { "HDTVI",  PVideoDevice::HD1080Width,PVideoDevice::HD1080Height},
    { "1080p",  PVideoDevice::HD1080Width,PVideoDevice::HD1080Height},

    { "CGA",    320,                      240                       },
    { "VGA",    640,                      480                       },
    { "WVGA",   854,                      480                       },
    { "SVGA",   800,                      600                       },
    { "XGA",    1024,                     768                       },
    { "SXGA",   1280,                     1024                      },
    { "WSXGA",  1440,                     900                       },
    { "SXGA+",  1400,                     1050                      },
    { "WSXGA+", 1680,                     1050                      },
    { "UXGA",   1600,                     1200                      },
    { "WUXGA",  1920,                     1200                      },
    { "QXGA",   2048,                     1536                      },
    { "WQXGA",  2560,                     1600                      },
};

bool PVideoFrameInfo::ParseSize(const PString & str, unsigned & width, unsigned & height)
{
  for (size_t i = 0; i < PARRAYSIZE(SizeTable); i++) {
    if (str *= SizeTable[i].name) {
      width = SizeTable[i].width;
      height = SizeTable[i].height;
      return true;
    }
  }

  return sscanf(str, "%ux%u", &width, &height) == 2 && width > 0 && height > 0;
}


PString PVideoFrameInfo::AsString(unsigned width, unsigned height)
{
  for (size_t i = 0; i < PARRAYSIZE(SizeTable); i++) {
    if (SizeTable[i].width == width && SizeTable[i].height == height)
      return SizeTable[i].name;
  }

  return psprintf("%ux%u", width, height);
}


PStringArray PVideoFrameInfo::GetSizeNames()
{
  PStringArray names(PARRAYSIZE(SizeTable));
  for (size_t i = 0; i < PARRAYSIZE(SizeTable); i++)
    names[i] = SizeTable[i].name;
  return names;
}


///////////////////////////////////////////////////////////////////////////////
// PVideoDevice

PVideoDevice::PVideoDevice()
{
  m_lastError = 0;

  m_videoFormat = Auto;
  m_channelNumber = -1;  // -1 will find the first working channel number.
  m_nativeVerticalFlip = false;

  m_converter = NULL;
}

PVideoDevice::~PVideoDevice()
{
  if (m_converter)
    delete m_converter;
}


void PVideoDevice::PrintOn(ostream & strm) const
{
  strm << GetClass() << " &" << this << ' ';
  PVideoFrameInfo::PrintOn(strm);
  strm << " [" << m_deviceName << "] {";

  if (m_channelNumber >= 0)
    strm << "channel=" << m_channelNumber << ',';

  if (m_converter) {
    strm << "converted";
    if (m_converter->GetVFlipState())
      strm << ",flipped";
  }
  else 
    strm << "native";

  strm << '}';
}


PVideoDevice::Attributes::Attributes()
  : m_brightness(-1)
  , m_contrast(-1)
  , m_saturation(-1)
  , m_hue(-1)
  , m_gamma(-1)
  , m_exposure(-1)
{
}


PVideoDevice::OpenArgs::OpenArgs()
  : pluginMgr(NULL),
    deviceName("#1"),
    videoFormat(Auto),
    channelNumber(-1),
    colourFormat(PVideoFrameInfo::YUV420P()),
    convertFormat(true),
    rate(0),
    width(CIFWidth),
    height(CIFHeight),
    convertSize(true),
    resizeMode(eScale),
    flip(false)
{
}


PString PVideoDevice::GetDeviceNameFromOpenArgs(const OpenArgs & args) const
{
  if (args.deviceName[(PINDEX)0] != '#')
    return args.deviceName;
  
  PStringArray devices = GetDeviceNames();
  PINDEX id = args.deviceName.Mid(1).AsUnsigned();
  if (id == 0 || id > devices.GetSize())
    return PString::Empty();
  
  return devices[id-1];
}


PBoolean PVideoDevice::OpenFull(const OpenArgs & args, PBoolean startImmediate)
{
  if (!Open(GetDeviceNameFromOpenArgs(args), false))
    return false;

  if (!SetVideoFormat(args.videoFormat))
    return false;

  if (!SetChannel(args.channelNumber))
    return false;

  if (args.convertFormat) {
    if (!SetColourFormatConverter(args.colourFormat))
      return false;
  }
  else {
    if (!SetColourFormat(args.colourFormat))
      return false;
  }

  if (args.rate > 0) {
    if (!SetFrameRate(args.rate))
      return false;
  }

  if (args.convertSize) {
    if (!SetFrameSizeConverter(args.width, args.height, args.resizeMode))
      return false;
  }
  else {
    if (!SetFrameSize(args.width, args.height))
      return false;
  }

  if (!SetVFlipState(args.flip))
    return false;

  SetAttributes(args.m_attributes);

  if (startImmediate)
    return Start();

  return true;
}


PBoolean PVideoDevice::Close()
{
  return true;  
}


PBoolean PVideoDevice::Start()
{
  return true;
}


PBoolean PVideoDevice::Stop()
{
  return true;
}


PBoolean PVideoDevice::SetVideoFormat(VideoFormat videoFmt)
{
  m_videoFormat = videoFmt;
  return true;
}


PVideoDevice::VideoFormat PVideoDevice::GetVideoFormat() const
{
  return m_videoFormat;
}


int PVideoDevice::GetNumChannels()
{
  return 1;
}


PStringArray PVideoDevice::GetChannelNames()
{
  int numChannels = GetNumChannels();
  PStringArray names(numChannels);
  for (int c = 0; c < numChannels; ++c)
    names[c] = PString((char)('A'+c));
  return names;
}


PBoolean PVideoDevice::SetChannel(int newChannelNumber)
{
  if (newChannelNumber < 0) { // No change
    int numChannels = GetNumChannels();
    if (m_channelNumber >= 0 && m_channelNumber < numChannels)
      return true;

    // Must change
    for (int c = 0; c < numChannels; c++) {
      if (SetChannel(c))
        return true;
    }

    PTRACE(2, "Cannot set any possible channel number on " << *this);
    return false;
  }

  if (newChannelNumber >= GetNumChannels()) {
    PTRACE(2, "SetChannel number (" << newChannelNumber << ") too large on " << *this);
    return false;
  }

  m_channelNumber = newChannelNumber;
  return true;
}


int PVideoDevice::GetChannel() const
{
  return m_channelNumber;
}


bool PVideoDevice::SetFrameInfoConverter(const PVideoFrameInfo & info)
{
  if (!SetColourFormatConverter(info.GetColourFormat())) {
    PTRACE(1, "Could not set colour format in "
           << (CanCaptureVideo() ? "grabber" : "display") << " to " << info << " on " << *this);
    return false;
  }

  if (!SetFrameSizeConverter(info.GetFrameWidth(), info.GetFrameHeight(), info.GetResizeMode())) {
    PTRACE(1, "Could not set frame size in "
           << (CanCaptureVideo() ? "grabber" : "display") << " to " << info << " on " << *this);
    return false;
  }

  if (info.GetFrameRate() != 0) {
    if (!SetFrameRate(info.GetFrameRate())) {
      PTRACE(1, "Could not set frame rate in "
           << (CanCaptureVideo() ? "grabber" : "display") << " to " << info << " on " << *this);
      return false;
    }
  }

  PTRACE(4, "Video " << (CanCaptureVideo() ? "grabber" : "display") << " frame info set on " << *this);
  return true;
}


PBoolean PVideoDevice::SetColourFormatConverter(const PString & newColourFmt)
{
  if (m_converter != NULL) {
    if (CanCaptureVideo()) {
      if (m_converter->GetDstColourFormat() == newColourFmt)
        return true;
    }
    else {
      if (m_converter->GetSrcColourFormat() == newColourFmt)
        return true;
    }
  }
  else {
    if (m_colourFormat == newColourFmt)
      return true;
  }

  PString newColourFormat = newColourFmt; // make copy, just in case newColourFmt is reference to member colourFormat

  if (!SetColourFormat(newColourFormat) &&
        (m_preferredColourFormat.IsEmpty() || !SetColourFormat(m_preferredColourFormat))) {
    /************************
      Eventually, need something more sophisticated than this, but for the
      moment pick the known colour formats that the device is very likely to
      support and then look for a conversion routine from that to the
      destination format.

      What we really want is some sort of better heuristic that looks at
      computational requirements of each converter and picks a pair of formats
      that the hardware supports and uses the least CPU.
    */

    PINDEX knownFormatIdx = 0;
    while (!SetColourFormat(ColourFormatBPPTab[knownFormatIdx].colourFormat)) {
      if (++knownFormatIdx >= PARRAYSIZE(ColourFormatBPPTab)) {
        PTRACE(2, "SetColourFormatConverter FAILED for " << newColourFormat << " on " << *this);
        return false;
      }
    }
  }

  PVideoFrameInfo src = *this;
  PVideoFrameInfo dst = *this;

  if (m_converter != NULL) {
    m_converter->GetSrcFrameInfo(src);
    m_converter->GetDstFrameInfo(dst);
    delete m_converter;
    m_converter = NULL;
  }

  if (m_nativeVerticalFlip || m_colourFormat != newColourFormat) {
    if (CanCaptureVideo()) {
      src.SetColourFormat(m_colourFormat);
      dst.SetColourFormat(newColourFormat);
    }
    else {
      src.SetColourFormat(newColourFormat);
      dst.SetColourFormat(m_colourFormat);
    }

    m_converter = PColourConverter::Create(src, dst);
    if (m_converter == NULL) {
      PTRACE(2, "SetColourFormatConverter failed to create converter from " << src << " to " << dst << " on " << *this);
      return false;
    }

    m_converter->SetVFlipState(m_nativeVerticalFlip);
  }

  PTRACE(3, "SetColourFormatConverter success, from " << src << " to " << dst << " on " << *this);

  return true;
}


PBoolean PVideoDevice::GetVFlipState()
{
  if (m_converter != NULL)
    return m_converter->GetVFlipState() ^ m_nativeVerticalFlip;

  return m_nativeVerticalFlip;
}


PBoolean PVideoDevice::SetVFlipState(PBoolean newVFlip)
{
  if (newVFlip && m_converter == NULL) {
    m_converter = PColourConverter::Create(*this, *this);
    if (PAssertNULL(m_converter) == NULL)
      return false;
  }

  if (m_converter != NULL)
    m_converter->SetVFlipState(newVFlip ^ m_nativeVerticalFlip);

  return true;
}


PBoolean PVideoDevice::GetFrameSizeLimits(unsigned & minWidth,
                                      unsigned & minHeight,
                                      unsigned & maxWidth,
                                      unsigned & maxHeight) 
{
  minWidth = minHeight = 1;
  maxWidth = maxHeight = UINT_MAX;
  return false;
}


PBoolean PVideoDevice::SetFrameSizeConverter(unsigned width, unsigned height, ResizeMode resizeMode)
{
  // Try and get the most compatible physical frame size to convert from/to
  if (!SetNearestFrameSize(width, height)) {
    PTRACE(1, "Cannot set an apropriate size to scale from on " << *this);
    return false;
  }

  // Now create the converter ( if not already exist)
  if (m_converter == NULL) {
    if (!m_nativeVerticalFlip && m_frameWidth == width && m_frameHeight == height) {
      PTRACE(4,"No converter required for " << width << 'x' << height << " on " << *this);
      return true;
    }

    PVideoFrameInfo src = *this;
    PVideoFrameInfo dst = *this;
    if (CanCaptureVideo())
      dst.SetFrameSize(width, height);
    else
      src.SetFrameSize(width, height);
    dst.SetResizeMode(resizeMode);
    m_converter = PColourConverter::Create(src, dst);
    if (m_converter == NULL) {
      PTRACE(1, "SetFrameSizeConverter Colour converter creation failed on " << *this);
      return false;
    }
  }
  else {
    if (CanCaptureVideo())
      m_converter->SetDstFrameSize(width, height);
    else
      m_converter->SetSrcFrameSize(width, height);
    m_converter->SetResizeMode(resizeMode);
  }

  m_converter->SetVFlipState(m_nativeVerticalFlip);

#if PTRACING
  static const unsigned level = 3;
  if (PTrace::CanTrace(level)) {
    PVideoFrameInfo src, dst;
    m_converter->GetSrcFrameInfo(src);
    m_converter->GetDstFrameInfo(dst);
    PTRACE_BEGIN(level) << "Colour converter used from " << src << " to " << dst << " on " << *this << PTrace::End;
  }
#endif

  return true;
}


PBoolean PVideoDevice::SetNearestFrameSize(unsigned width, unsigned height)
{
  unsigned minWidth, minHeight, maxWidth, maxHeight;
  if (GetFrameSizeLimits(minWidth, minHeight, maxWidth, maxHeight)) {
    if (width < minWidth)
      width = minWidth;
    else if (width > maxWidth)
      width = maxWidth;

    if (height < minHeight)
      height = minHeight;
    else if (height > maxHeight)
      height = maxHeight;
  }

  return SetFrameSize(width, height);
}


PBoolean PVideoDevice::SetFrameSize(unsigned width, unsigned height)
{
#if PTRACING
  unsigned oldWidth = m_frameWidth;
  unsigned oldHeight = m_frameHeight;
#endif

  if (!PVideoFrameInfo::SetFrameSize(width, height))
    return false;

  if (m_converter != NULL && !m_converter->SetFrameSize(width, height)) {
    PTRACE(1, "SetFrameSize with converter failed with " << width << 'x' << height << " on " << *this);
    return false;
  }

  PTRACE_IF(3, oldWidth != m_frameWidth || oldHeight != m_frameHeight,
            "SetFrameSize to " << m_frameWidth << 'x' << m_frameHeight << " on " << *this);
  return true;
}


PBoolean PVideoDevice::GetFrameSize(unsigned & width, unsigned & height) const
{
  // Channels get very upset at this not returning the output size.
  if (m_converter == NULL)
    return PVideoFrameInfo::GetFrameSize(width, height);
  return CanCaptureVideo() ? m_converter->GetDstFrameSize(width, height)
                           : m_converter->GetSrcFrameSize(width, height);
}


PString PVideoDevice::GetColourFormat() const
{
  if (m_converter == NULL)
    return PVideoFrameInfo::GetColourFormat();
  return CanCaptureVideo() ? m_converter->GetDstColourFormat()
                           : m_converter->GetSrcColourFormat();
}


PINDEX PVideoDevice::GetMaxFrameBytes()
{
  return GetMaxFrameBytesConverted(CalculateFrameBytes(m_frameWidth, m_frameHeight, m_colourFormat));
}


PINDEX PVideoDevice::GetMaxFrameBytesConverted(PINDEX rawFrameBytes) const
{
  if (m_converter == NULL)
    return rawFrameBytes;

  PINDEX srcFrameBytes = m_converter->GetMaxSrcFrameBytes();
  PINDEX dstFrameBytes = m_converter->GetMaxDstFrameBytes();
  PINDEX convertedFrameBytes = PMAX(srcFrameBytes, dstFrameBytes);
  return PMAX(rawFrameBytes, convertedFrameBytes);
}


bool PVideoDevice::GetAttributes(Attributes &)
{
  return false;
}


bool PVideoDevice::SetAttributes(const Attributes &)
{
  return false;
}


PBoolean PVideoDevice::SetVideoChannelFormat (int newNumber, VideoFormat newFormat) 
{
  PBoolean err1, err2;

  err1 = SetChannel (newNumber);
  err2 = SetVideoFormat (newFormat);
  
  return (err1 && err2);
}

PStringArray PVideoDevice::GetDeviceNames() const
{
  return PStringArray();
}


PString PVideoDevice::ParseDeviceNameTokenString(const char * token, const char * defaultValue)
{
  PString search = token;
  search += '=';
  PINDEX pos = m_deviceName.Find(search);
  if (pos == P_MAX_INDEX)
    return defaultValue;

  pos += search.GetLength();
  PINDEX quote = m_deviceName.FindLast('"');
  return PString(PString::Literal, m_deviceName(pos, quote > pos ? quote : P_MAX_INDEX));
}


int PVideoDevice::ParseDeviceNameTokenInt(const char * token, int defaultValue)
{
  PString search = token;
  search += '=';
  PINDEX pos = m_deviceName.Find(search);
  return pos != P_MAX_INDEX ? m_deviceName.Mid(pos+search.GetLength()).AsInteger() : defaultValue;
}


uint64_t PVideoDevice::ParseDeviceNameTokenUnsigned(const char * token, uint64_t defaultValue)
{
  PString search = token;
  search += '=';
  PINDEX pos = m_deviceName.Find(search);
  return pos != P_MAX_INDEX ? m_deviceName.Mid(pos+search.GetLength()).AsUnsigned64() : defaultValue;
}


/////////////////////////////////////////////////////////////////////////////////////////////

void PVideoControlInfo::PrintOn(ostream & strm) const
{
  strm << m_type << ": min=" << m_minimum << ", max=" << m_maximum << ", step=" << m_step << ", reset=" << m_reset;
}


int PVideoControlInfo::SetCurrent(int current)
{
  if (current < m_minimum)
    m_current = m_minimum;
  else if (current > m_maximum)
    m_current = m_maximum;
  else
    m_current = current;
  return m_current;
}


////////////////////////////////////////////////////////////////////////////////////////////

PVideoInteractionInfo::PVideoInteractionInfo()
  : m_type(InteractOther)
{
}


void PVideoInteractionInfo::PrintOn(ostream & strm) const
{
  strm << AsString(m_type);
}


PString PVideoInteractionInfo::AsString(const Type & ctype)
{
  switch (ctype) {
    case InteractKey:
      return "Remote Key Press";
    case InteractMouse:
      return "Remote Mouse Move/Click";
    case InteractNavigate:
      return "Remote Navigation";
    case InteractRTSP:
      return "Remote RTSP Commands";
    case InteractOther:
      return "Custom/Other";
    default :
      return PString::Empty();
  }
}

///////////////////////////////////////////////////////////////////////////////
// PVideoOutputDevice

PVideoOutputDevice::PVideoOutputDevice()
{
}


PBoolean PVideoOutputDevice::CanCaptureVideo() const
{
  return false;
}


PBoolean PVideoOutputDevice::GetPosition(int &, int &) const
{
  return false;
}


bool PVideoOutputDevice::SetPosition(int, int)
{
  return false;
}


///////////////////////////////////////////////////////////////////////////////
// PVideoOutputDeviceRGB

PVideoOutputDeviceRGB::PVideoOutputDeviceRGB()
  : m_bytesPerPixel(3)
  , m_scanLineWidth(((m_frameWidth*3+3)/4)*4)
  , m_swappedRedAndBlue(false)
{
  m_colourFormat = "RGB24";
}


PBoolean PVideoOutputDeviceRGB::SetColourFormat(const PString & colourFormat)
{
  PWaitAndSignal lock(m_mutex);

  PINDEX newBytesPerPixel;

  if (colourFormat *= "RGB32") {
    newBytesPerPixel = 4;
    m_swappedRedAndBlue = false;
  }
  else if (colourFormat *= "RGB24") {
    newBytesPerPixel = 3;
    m_swappedRedAndBlue = false;
  }
  else if (colourFormat *= "BGR32") {
    newBytesPerPixel = 4;
    m_swappedRedAndBlue = true;
  }
  else if (colourFormat *= "BGR24") {
    newBytesPerPixel = 3;
    m_swappedRedAndBlue = true;
  }
  else
    return false;

  if (!PVideoOutputDevice::SetColourFormat(colourFormat))
    return false;

  m_bytesPerPixel = newBytesPerPixel;
  m_scanLineWidth = ((m_frameWidth*m_bytesPerPixel+3)/4)*4;
  return m_frameStore.SetSize(m_frameHeight*m_scanLineWidth);
}


PBoolean PVideoOutputDeviceRGB::SetFrameSize(unsigned width, unsigned height)
{
  PWaitAndSignal lock(m_mutex);

  if (m_frameWidth == width && m_frameHeight == height)
    return true;

  if (!PVideoOutputDevice::SetFrameSize(width, height))
    return false;

  m_scanLineWidth = ((m_frameWidth*m_bytesPerPixel+3)/4)*4;
  return m_frameStore.SetSize(m_frameHeight*m_scanLineWidth);
}


PINDEX PVideoOutputDeviceRGB::GetMaxFrameBytes()
{
  PWaitAndSignal lock(m_mutex);
  return GetMaxFrameBytesConverted(m_frameStore.GetSize());
}


PBoolean PVideoOutputDeviceRGB::SetFrameData(const FrameData & frameData)
{
  {
    PWaitAndSignal lock(m_mutex);

    if (!IsOpen())
      return false;

    if (frameData.x+frameData.width > m_frameWidth || frameData.y+frameData.height > m_frameHeight || PAssertNULL(frameData.pixels) == NULL)
      return false;

    if (frameData.x == 0 && frameData.width == m_frameWidth && frameData.y == 0 && frameData.height == m_frameHeight) {
      if (m_converter != NULL)
        m_converter->Convert(frameData.pixels, m_frameStore.GetPointer());
      else
        memcpy(m_frameStore.GetPointer(), frameData.pixels, frameData.height*m_scanLineWidth);
    }
    else {
      if (m_converter != NULL) {
        PAssertAlways("Converted output of partial RGB frame not supported");
        return false;
      }

      if (frameData.x == 0 && frameData.width == m_frameWidth)
        memcpy(m_frameStore.GetPointer() + frameData.y*m_scanLineWidth, frameData.pixels, frameData.height*m_scanLineWidth);
      else {
        for (unsigned dy = 0; dy < frameData.height; dy++)
          memcpy(m_frameStore.GetPointer() + (frameData.y+dy)*m_scanLineWidth + frameData.x*m_bytesPerPixel,
                 frameData.pixels + dy*frameData.width*m_bytesPerPixel, frameData.width*m_bytesPerPixel);
      }
    }
  }

  if (frameData.partialFrame)
    return true;

  return FrameComplete();
}


///////////////////////////////////////////////////////////////////////////////
// PVideoInputDevice

PBoolean PVideoInputDevice::CanCaptureVideo() const
{
  return true;
}


PStringArray PVideoInputDevice::GetDriverNames(PPluginManager * pluginMgr)
{
  return PPluginManager::GetPluginsProviding(pluginMgr, PPlugin_PVideoInputDevice::ServiceType(), false);
}


PStringArray PVideoInputDevice::GetDriversDeviceNames(const PString & driverName, PPluginManager * pluginMgr)
{
  // Give precedence to drivers like camera grabbers, Window
  static const char * const PrioritisedDrivers[] = {
#ifdef P_DIRECT_SHOW_DRIVER
    P_DIRECT_SHOW_DRIVER,
#endif
#ifdef P_VIDEO_FOR_WINDOWS_DRIVER
    P_VIDEO_FOR_WINDOWS_DRIVER,
#endif
#if !defined(WIN32) && !defined(P_MACOSX)
    "V4L",
    "V4L2",
    "1394DC",
    "1394AVC",
    "BSDCAPTURE",
#endif
#ifdef P_MAC_VIDEO_DRIVER
    P_MAC_VIDEO_DRIVER,
#endif
    P_FAKE_VIDEO_DRIVER,
#ifdef P_APPLICATION_VIDEO_DRIVER
    P_APPLICATION_VIDEO_DRIVER,
#endif
#ifdef P_MEDIA_FILE_DRIVER
    P_MEDIA_FILE_DRIVER,
#endif
#ifdef P_VIDEO_FILE_DRIVER
    P_VIDEO_FILE_DRIVER,
#endif
    NULL
  };
  return PPluginManager::GetPluginDeviceNames(pluginMgr, driverName, PPlugin_PVideoInputDevice::ServiceType(), 0, PrioritisedDrivers);
}


PVideoInputDevice * PVideoInputDevice::CreateDevice(const PString &driverName, PPluginManager * pluginMgr)
{
  return PPluginManager::CreatePluginAs<PVideoInputDevice>(pluginMgr, driverName, PPlugin_PVideoInputDevice::ServiceType());
}


PVideoInputDevice * PVideoInputDevice::CreateDeviceByName(const PString & deviceName, const PString & driverName, PPluginManager * pluginMgr)
{
  return PPluginManager::CreatePluginAs<PVideoInputDevice>(pluginMgr, driverName.IsEmpty() ? deviceName : driverName, PPlugin_PVideoInputDevice::ServiceType());
}


bool PVideoInputDevice::GetDeviceCapabilities(Capabilities * /*capabilities*/) const
{
  return false;
}


bool PVideoInputDevice::GetDeviceCapabilities(const PString & deviceName, Capabilities * caps, PPluginManager * pluginMgr)
{
  return GetDeviceCapabilities(deviceName, "*", caps, pluginMgr);
}


bool PVideoInputDevice::GetDeviceCapabilities(const PString & deviceName, const PString & driverName, Capabilities * caps, PPluginManager * pluginMgr)
{
  if (pluginMgr == NULL)
    pluginMgr = &PPluginManager::GetPluginManager();

  return pluginMgr->GetPluginsDeviceCapabilities(PPlugin_PVideoInputDevice::ServiceType(), driverName, deviceName, caps);
}


PVideoInputDevice::Capabilities::Capabilities()
  : m_channels(0)
  , m_brightness(false)
  , m_contrast(false)
  , m_saturation(false)
  , m_hue(false)
  , m_gamma(false)
  , m_exposure(false)
{
}


void PVideoInputDevice::Capabilities::PrintOn(ostream & strm) const
{
  std::streamsize indent = strm.precision();

  strm << setw(indent) << ' ';
  if (m_frameSizes.empty())
    strm << "No frame sizes.\n";
  else {
    strm << "Frame Sizes:\n";
    for (list<PVideoFrameInfo>::const_iterator it = m_frameSizes.begin(); it != m_frameSizes.end(); ++it)
      strm << setw(indent+2) << ' ' << *it << '\n';
  }

  strm << setw(indent) << ' ';
  if (m_controls.empty())
    strm << "No controls.\n";
  else {
    strm << "Controls:\n";
    for (list<PVideoControlInfo>::const_iterator it = m_controls.begin(); it != m_controls.end(); ++it)
      strm << setw(indent+2) << ' ' << *it << '\n';
  }

  strm << setw(indent) << ' ';
  if (m_interactions.empty())
    strm << "No interactions.\n";
  else {
    strm << "Interactions:\n";
    for (list<PVideoInteractionInfo>::const_iterator it = m_interactions.begin(); it != m_interactions.end(); ++it)
      strm << setw(indent+2) << ' ' << *it << '\n';
  }
}


PVideoInputDevice * PVideoInputDevice::CreateOpenedDevice(const PString & driverName,
                                                          const PString & deviceName,
                                                          bool startImmediate,
                                                          PPluginManager * pluginMgr)
{
  PString adjustedDeviceName = deviceName;
  PVideoInputDevice * device = CreateDeviceWithDefaults<PVideoInputDevice>(adjustedDeviceName, driverName, pluginMgr);
  if (device == NULL)
    return NULL;

  PTRACE(4, device, "Found video input device: " << device->GetClass());
  if (device->Open(adjustedDeviceName, startImmediate))
    return device;

  delete device;
  return NULL;
}


PVideoInputDevice * PVideoInputDevice::CreateOpenedDevice(const OpenArgs & args,
                                                          bool startImmediate)
{
  OpenArgs adjustedArgs = args;
  PVideoInputDevice * device = CreateDeviceWithDefaults<PVideoInputDevice>(adjustedArgs.deviceName, args.driverName, NULL);
  if (device == NULL)
    return NULL;

  device->SetColourFormat(args.colourFormat);
  device->SetFrameSize(args.width, args.height);
  if (device->OpenFull(adjustedArgs, startImmediate))
    return device;

  delete device;
  return NULL;
}


PBoolean PVideoInputDevice::SetNearestFrameSize(unsigned width, unsigned height)
{
  if (PVideoDevice::SetNearestFrameSize(width, height))
    return true;

  // Get the discrete sizes grabber is capable of
  Capabilities caps;
  if (!GetDeviceCapabilities(&caps))
    return false;

  std::list<PVideoFrameInfo>::iterator it;

  // First try and pick one with the same width
  for (it = caps.m_frameSizes.begin(); it != caps.m_frameSizes.end(); ++it) {
    if (it->GetFrameWidth() == width)
      return SetFrameSize(width, it->GetFrameHeight());
  }

  // Then try for the same height
  for (it = caps.m_frameSizes.begin(); it != caps.m_frameSizes.end(); ++it) {
    if (it->GetFrameHeight() == height)
      return SetFrameSize(it->GetFrameWidth(), height);
  }

  // Then try for double the size
  for (it = caps.m_frameSizes.begin(); it != caps.m_frameSizes.end(); ++it) {
    unsigned w, h;
    it->GetFrameSize(w, h);
    if (w == width*2 && h == height*2)
      return SetFrameSize(w, h);
  }

  // Then try for half the size
  for (it = caps.m_frameSizes.begin(); it != caps.m_frameSizes.end(); ++it) {
    unsigned w, h;
    it->GetFrameSize(w, h);
    if (w == width/2 && h == height/2)
      return SetFrameSize(w, h);
  }

  // Now try and pick one that has the nearest number of pixels in total.
  unsigned pixels = width*height;
  unsigned widthToUse = 0, heightToUse = 0;
  int diff = INT_MAX;
  for (it = caps.m_frameSizes.begin(); it != caps.m_frameSizes.end(); ++it) {
    unsigned w, h;
    it->GetFrameSize(w, h);
    int d = w*h - pixels;
    if (d < 0)
      d = -d;
    // Ensure we don't pick one dimension greater and one 
    // lower because we can't shrink one and grow the other.
    if (diff > d && ((w < width && h < height) || (w > width && h > height))) {
      diff = d;
      widthToUse = w;
      heightToUse = h;
    }
  }

  if (widthToUse == 0)
    return false;

  return SetFrameSize(widthToUse, heightToUse);
}


PBoolean PVideoInputDevice::GetFrame(BYTE * buffer, PINDEX & bytesReturned, bool & keyFrame, bool wait)
{
  return InternalGetFrameData(buffer, bytesReturned, keyFrame, wait);
}


PBoolean PVideoInputDevice::GetFrame(PBYTEArray & frame)
{
  PINDEX size = GetMaxFrameBytes();
  if (size == 0) {
    PTRACE(2, "Frame size in bytes not available on " << *this);
    return false;
  }

  PINDEX returned;
  bool keyFrame = true;
  if (!InternalGetFrameData(frame.GetPointer(size), returned, keyFrame, true))
    return false;

  frame.SetSize(returned);
  return true;
}


PBoolean PVideoInputDevice::GetFrame(PBYTEArray & frame, unsigned & width, unsigned & height)
{
  return GetFrame(frame) && GetFrameSize(width, height);
}


PBoolean PVideoInputDevice::GetFrameData(BYTE * buffer, PINDEX * bytesReturned, bool & keyFrame)
{
  PINDEX dummy;
  return InternalGetFrameData(buffer, bytesReturned != NULL ? *bytesReturned : dummy, keyFrame, true);
}


PBoolean PVideoInputDevice::GetFrameData(BYTE * buffer, PINDEX * bytesReturned)
{
  PINDEX dummy;
  bool keyFrame = true;
  return InternalGetFrameData(buffer, bytesReturned != NULL ? *bytesReturned : dummy, keyFrame, true);
}


bool PVideoInputDevice::GetFrameDataNoDelay(BYTE * buffer, PINDEX * bytesReturned, bool & keyFrame)
{
  PINDEX dummy;
  return InternalGetFrameData(buffer, bytesReturned != NULL ? *bytesReturned : dummy, keyFrame, false);
}


bool PVideoInputDevice::GetFrameDataNoDelay(BYTE * buffer, PINDEX * bytesReturned)
{
  PINDEX dummy;
  bool keyFrame = true;
  return InternalGetFrameData(buffer, bytesReturned != NULL ? *bytesReturned : dummy, keyFrame, false);
}


bool PVideoInputDevice::FlowControl(const void * /*flowData*/)
{
    return false;
}


bool PVideoInputDevice::SetCaptureMode(unsigned)
{
  return false;
}


int PVideoInputDevice::GetCaptureMode() const
{
  return -1;
}


bool PVideoInputDevice::SetControl(PVideoControlInfo::Types, int, ControlMode)
{
  return false;
}


bool PVideoOutputDevice::SetFrameData(unsigned x, unsigned y,
                                      unsigned width, unsigned height,
                                      const BYTE * pixels, bool endFrame)
{
  FrameData frameData;
  frameData.x = x;
  frameData.y = y;
  frameData.width = width;
  frameData.height = height;
  frameData.pixels = pixels;
  frameData.partialFrame = !endFrame;
  return SetFrameData(frameData);
}


bool PVideoOutputDevice::SetFrameData(unsigned x, unsigned y,
                                      unsigned width, unsigned height,
                                      const BYTE * pixels, bool endFrame,
                                      bool & keyFrameNeeded)
{
  FrameData frameData;
  frameData.x = x;
  frameData.y = y;
  frameData.width = width;
  frameData.height = height;
  frameData.pixels = pixels;
  frameData.partialFrame = !endFrame;
  frameData.keyFrameNeeded = &keyFrameNeeded;
  return SetFrameData(frameData);
}


PBoolean PVideoOutputDevice::DisableDecode() 
{
  return false;
}


////////////////////////////////////////////////////////////////////////////////////////////

void PVideoInputDeviceIndirect::SetActualDevice(PVideoInputDevice * actualDevice, bool autoDelete)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  if (m_actualDevice == actualDevice)
    return;

  if (m_autoDeleteActualDevice)
    delete m_actualDevice;

  m_actualDevice = actualDevice;
  m_autoDeleteActualDevice = autoDelete;

  if (m_actualDevice != NULL) {
    PTRACE(3, "Actual video device set to " << *m_actualDevice);
    m_actualDevice->SetFrameInfoConverter(*this);
  }
  else
    PTRACE(3, "Actual video device reset");
}


PVideoInputDevice * PVideoInputDeviceIndirect::GetActualDevice() const
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice;
}


PObject::Comparison PVideoInputDeviceIndirect::Compare(const PObject & obj) const
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->Compare(obj) : LessThan;
}


void PVideoInputDeviceIndirect::PrintOn(ostream & strm) const
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  if (m_actualDevice != NULL)
    m_actualDevice->PrintOn(strm);
  else
    strm << "PVideoInputDeviceIndirect: <null>";
}


PBoolean PVideoInputDeviceIndirect::SetFrameSize(unsigned width, unsigned height)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return PVideoInputDevice::SetFrameSize(width, height) && m_actualDevice != NULL && m_actualDevice->SetFrameSize(width, height);
}


PBoolean PVideoInputDeviceIndirect::SetFrameSar(unsigned width, unsigned height)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return PVideoInputDevice::SetFrameSar(width, height) && m_actualDevice != NULL && m_actualDevice->SetFrameSar(width, height);
}


PBoolean PVideoInputDeviceIndirect::SetFrameRate(unsigned rate)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return PVideoInputDevice::SetFrameRate(rate) && m_actualDevice != NULL && m_actualDevice->SetFrameRate(rate);
}


PBoolean PVideoInputDeviceIndirect::SetColourFormat(const PString & colourFormat)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return PVideoInputDevice::SetColourFormat(colourFormat) && m_actualDevice != NULL && m_actualDevice->SetColourFormat(colourFormat);
}


void PVideoInputDeviceIndirect::SetResizeMode(ResizeMode mode)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  PVideoInputDevice::SetResizeMode(mode);
  if (m_actualDevice != NULL)
    m_actualDevice->SetResizeMode(mode);
}


PINDEX PVideoInputDeviceIndirect::CalculateFrameBytes() const
{
  PINDEX size = PVideoInputDevice::CalculateFrameBytes();
  PWaitAndSignal lock(m_actualDeviceMutex);
  if (m_actualDevice == NULL)
    return size;
  return std::max(m_actualDevice->CalculateFrameBytes(), size);
}


bool PVideoInputDeviceIndirect::Parse(const PString & str)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return PVideoInputDevice::Parse(str) && m_actualDevice != NULL && m_actualDevice->Parse(str);
}


PString PVideoInputDeviceIndirect::GetDeviceName() const
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->GetDeviceName() : PVideoInputDevice::GetDeviceName();
}


PStringArray PVideoInputDeviceIndirect::GetDeviceNames() const
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->GetDeviceNames() : PVideoInputDevice::GetDeviceNames();
}


PBoolean PVideoInputDeviceIndirect::OpenFull(const OpenArgs & args, PBoolean startImmediate)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->OpenFull(args, startImmediate);
}


PBoolean PVideoInputDeviceIndirect::Open(const PString & deviceName, PBoolean startImmediate)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->Open(deviceName, startImmediate);
}


PBoolean PVideoInputDeviceIndirect::IsOpen()
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->IsOpen();
}


PBoolean PVideoInputDeviceIndirect::Close()
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->Close();
}


PBoolean PVideoInputDeviceIndirect::Start()
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->Start();
}


PBoolean PVideoInputDeviceIndirect::Stop()
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->Stop();
}


PBoolean PVideoInputDeviceIndirect::SetVideoFormat(VideoFormat videoFormat)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return PVideoInputDevice::SetVideoFormat(videoFormat) && m_actualDevice != NULL && m_actualDevice->SetVideoFormat(videoFormat);
}


int PVideoInputDeviceIndirect::GetNumChannels()
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->GetNumChannels() : PVideoInputDevice::GetNumChannels();
}


PStringArray PVideoInputDeviceIndirect::GetChannelNames()
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->GetChannelNames() : PVideoInputDevice::GetChannelNames();
}


PBoolean PVideoInputDeviceIndirect::SetChannel(int channelNumber)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return PVideoInputDevice::SetChannel(channelNumber) && m_actualDevice != NULL && m_actualDevice->SetChannel(channelNumber);
}


int PVideoInputDeviceIndirect::GetChannel() const
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->GetChannel() : PVideoInputDevice::GetChannel();
}


PBoolean PVideoInputDeviceIndirect::SetVFlipState(PBoolean newVFlipState)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return PVideoInputDevice::SetVFlipState(newVFlipState) && m_actualDevice != NULL && m_actualDevice->SetVFlipState(newVFlipState);
}


PBoolean PVideoInputDeviceIndirect::GetFrameSizeLimits(unsigned & minWidth, unsigned & minHeight, unsigned & maxWidth, unsigned & maxHeight)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->GetFrameSizeLimits(minWidth, minHeight, maxWidth, maxHeight)
                                : PVideoInputDevice::GetFrameSizeLimits(minWidth, minHeight, maxWidth, maxHeight);
}


PBoolean PVideoInputDeviceIndirect::SetNearestFrameSize(unsigned width, unsigned height)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->SetNearestFrameSize(width, height) : PVideoInputDevice::SetNearestFrameSize(width, height);
}


bool PVideoInputDeviceIndirect::SetFrameInfoConverter(const PVideoFrameInfo & info)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  if (m_actualDevice == NULL)
    return PVideoInputDevice::SetFrameInfoConverter(info);

  if (!m_actualDevice->SetFrameInfoConverter(info))
    return false;

  *static_cast<PVideoFrameInfo *>(this) = *m_actualDevice;
  return true;
}


PBoolean PVideoInputDeviceIndirect::SetColourFormatConverter(const PString & colourFormat)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  if (m_actualDevice == NULL)
    return PVideoInputDevice::SetColourFormatConverter(colourFormat);

  if (!m_actualDevice->SetColourFormatConverter(colourFormat))
    return false;

  *static_cast<PVideoFrameInfo *>(this) = *m_actualDevice;
  return true;
}


PBoolean PVideoInputDeviceIndirect::SetFrameSizeConverter(unsigned width, unsigned height, ResizeMode resizeMode)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  if (m_actualDevice == NULL)
    return PVideoInputDevice::SetFrameSizeConverter(width, height, resizeMode);

  if (!m_actualDevice->SetFrameSizeConverter(width, height, resizeMode))
    return false;

  *static_cast<PVideoFrameInfo *>(this) = *m_actualDevice;
  return true;
}


int PVideoInputDeviceIndirect::GetLastError() const
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->GetLastError() : PVideoInputDevice::GetLastError();
}


bool PVideoInputDeviceIndirect::GetAttributes(Attributes & attributes)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->GetAttributes(attributes) : PVideoInputDevice::GetAttributes(attributes);
}


bool PVideoInputDeviceIndirect::SetAttributes(const Attributes & attributes)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->SetAttributes(attributes);
}


PBoolean PVideoInputDeviceIndirect::SetVideoChannelFormat(int channelNumber, VideoFormat videoFormat)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->SetVideoChannelFormat(channelNumber, videoFormat)
                                : PVideoInputDevice::SetVideoChannelFormat(channelNumber, videoFormat);
}


bool PVideoInputDeviceIndirect::GetDeviceCapabilities(Capabilities * capabilities) const
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->GetDeviceCapabilities(capabilities) : PVideoInputDevice::GetDeviceCapabilities(capabilities);
}


PBoolean PVideoInputDeviceIndirect::IsCapturing()
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->IsCapturing();
}


bool PVideoInputDeviceIndirect::InternalGetFrameData(BYTE * buffer, PINDEX & bytesReturned, bool & keyFrame, bool wait)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->GetFrame(buffer, bytesReturned, keyFrame, wait);
}


bool PVideoInputDeviceIndirect::FlowControl(const void * flowData)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->FlowControl(flowData);
}


bool PVideoInputDeviceIndirect::SetCaptureMode(unsigned mode)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->SetCaptureMode(mode);
}


int PVideoInputDeviceIndirect::GetCaptureMode() const
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL ? m_actualDevice->GetCaptureMode() : PVideoInputDevice::GetCaptureMode();
}


bool PVideoInputDeviceIndirect::SetControl(PVideoControlInfo::Types type, int value, ControlMode mode)
{
  PWaitAndSignal lock(m_actualDeviceMutex);
  return m_actualDevice != NULL && m_actualDevice->SetControl(type, value, mode);
}


////////////////////////////////////////////////////////////////////////////////////////////

PVideoInputEmulatedDevice::PVideoInputEmulatedDevice()
  : m_pacing(500)
  , m_fixedFrameRate(0)
  , m_frameRateAdjust(0)
  , m_frameNumber(0)
{
}


PVideoInputEmulatedDevice::~PVideoInputEmulatedDevice()
{
  Close();
}


PBoolean PVideoInputEmulatedDevice::Start()
{
  return true;
}


PBoolean PVideoInputEmulatedDevice::Stop()
{
  return true;
}


PBoolean PVideoInputEmulatedDevice::IsCapturing()
{
  return IsOpen();
}


bool PVideoInputEmulatedDevice::InternalGetFrameData(BYTE * buffer, PINDEX & bytesReturned, bool & keyFrame, bool wait)
{
  if (wait)
    m_pacing.Delay(1000/m_frameRate);

  if (!IsOpen()) {
    PTRACE(5, "InternalGetFrameData closed " << *this);
    return false;
  }

  keyFrame = true;

  if (m_fixedFrameRate > 0) {
    if (m_fixedFrameRate > m_frameRate) {
      m_frameRateAdjust += m_fixedFrameRate;
      while (m_frameRateAdjust > m_frameRate) {
        m_frameRateAdjust -= m_frameRate;
        ++m_frameNumber;
      }
      --m_frameNumber;
    }
    else if (m_fixedFrameRate < m_frameRate) {
      if (m_frameRateAdjust < m_frameRate)
        m_frameRateAdjust += m_fixedFrameRate;
      else {
        m_frameRateAdjust -= m_frameRate;
        --m_frameNumber;
      }
    }

    PTRACE(6, "Playing frame number " << m_frameNumber << " on " << *this);
  }

  PINDEX frameBytes = GetMaxFrameBytes();
  BYTE * readBuffer = m_converter != NULL ? m_frameStore.GetPointer(frameBytes) : buffer;

  if (!InternalReadFrameData(readBuffer)) {
    switch (m_channelNumber) {
      case Channel_PlayAndClose:
      default:
        PTRACE(4, "Completed play and close of " << *this);
        return false;

      case Channel_PlayAndRepeat:
        m_frameNumber = 0;
        // Reclaculate, in case derived class has altered these values
        frameBytes = GetMaxFrameBytes();
        readBuffer = m_converter != NULL ? m_frameStore.GetPointer(frameBytes) : buffer;
        if (!InternalReadFrameData(readBuffer))
          return false;
        break;

      case Channel_PlayAndKeepLast:
        PTRACE(4, "Completed play and keep last of " << *this);
        break;

      case Channel_PlayAndShowBlack:
        PTRACE(4, "Completed play and show black of " << *this);
        PColourConverter::FillYUV420P(0, 0,
                                      m_frameWidth, m_frameHeight,
                                      m_frameWidth, m_frameHeight,
                                      readBuffer,
                                      0, 0, 0);
        break;

      case Channel_PlayAndShowWhite:
        PTRACE(4, "Completed play and show white of " << *this);
        PColourConverter::FillYUV420P(0, 0,
                                      m_frameWidth, m_frameHeight,
                                      m_frameWidth, m_frameHeight,
                                      readBuffer,
                                      255, 255, 255);
        break;
    }
  }

  if (m_converter == NULL)
    bytesReturned = frameBytes;
  else {
    m_converter->SetSrcFrameSize(m_frameWidth, m_frameHeight);
    if (!m_converter->Convert(readBuffer, buffer, &bytesReturned)) {
      PTRACE(2, "Conversion failed with " << *m_converter << " on " << *this);
      return false;
    }
  }

  return true;
}


PBoolean PVideoInputEmulatedDevice::SetColourFormat(const PString & newFormat)
{
  return (m_colourFormat *= newFormat);
}


int PVideoInputEmulatedDevice::GetNumChannels() 
{
  return ChannelCount;  
}


PStringArray PVideoInputEmulatedDevice::GetChannelNames()
{
  PStringArray names(ChannelCount);
  names[0] = "Once, then close";
  names[1] = "Repeat";
  names[2] = "Once, then still";
  names[3] = "Once, then black";
  return names;
}


PBoolean PVideoInputEmulatedDevice::GetFrameSizeLimits(unsigned & minWidth,
                                                       unsigned & minHeight,
                                                       unsigned & maxWidth,
                                                       unsigned & maxHeight) 
{
  if (m_frameWidth == 0 || m_frameHeight == 0)
    return false;

  minWidth  = maxWidth  = m_frameWidth;
  minHeight = maxHeight = m_frameHeight;
  return true;
}


PBoolean PVideoInputEmulatedDevice::SetFrameRate(unsigned rate)
{
  return rate == m_frameRate;
}


PBoolean PVideoInputEmulatedDevice::SetFrameSize(unsigned width, unsigned height)
{
  return width == m_frameWidth && height == m_frameHeight;
}


////////////////////////////////////////////////////////////////////////////////////////////

PStringArray PVideoOutputDevice::GetDriverNames(PPluginManager * pluginMgr)
{
  return PPluginManager::GetPluginsProviding(pluginMgr, PPlugin_PVideoOutputDevice::ServiceType(), false);
}


PStringArray PVideoOutputDevice::GetDriversDeviceNames(const PString & driverName, PPluginManager * pluginMgr)
{
  // Give precedence to drivers like camera grabbers, Window
  static const char * const PrioritisedDrivers[] = {
#ifdef P_MSWIN_VIDEO_DRIVER
    P_MSWIN_VIDEO_DRIVER,
#endif
#ifdef P_SDL_VIDEO_DRIVER
    P_SDL_VIDEO_DRIVER,
#endif
    P_NULL_VIDEO_DRIVER,
#ifdef P_MEDIA_FILE_DRIVER
    P_MEDIA_FILE_DRIVER,
#endif
#ifdef P_VIDEO_FILE_DRIVER
    P_VIDEO_FILE_DRIVER,
#endif
    NULL
  };

  return PPluginManager::GetPluginDeviceNames(pluginMgr, driverName, PPlugin_PVideoOutputDevice::ServiceType(), 0, PrioritisedDrivers);
}


PVideoOutputDevice * PVideoOutputDevice::CreateDevice(const PString & driverName, PPluginManager * pluginMgr)
{
  return PPluginManager::CreatePluginAs<PVideoOutputDevice>(pluginMgr, driverName, PPlugin_PVideoOutputDevice::ServiceType());
}


PVideoOutputDevice * PVideoOutputDevice::CreateDeviceByName(const PString & deviceName, const PString & driverName, PPluginManager * pluginMgr)
{
  return PPluginManager::CreatePluginAs<PVideoOutputDevice>(pluginMgr, driverName.IsEmpty() ? deviceName : driverName, PPlugin_PVideoOutputDevice::ServiceType());
}


PVideoOutputDevice * PVideoOutputDevice::CreateOpenedDevice(const PString &driverName,
                                                            const PString &deviceName,
                                                            bool startImmediate,
                                                            PPluginManager * pluginMgr)
{
  PString adjustedDeviceName = deviceName;
  PVideoOutputDevice * device = CreateDeviceWithDefaults<PVideoOutputDevice>(adjustedDeviceName, driverName, pluginMgr);
  if (device == NULL)
    return NULL;

  if (device->Open(adjustedDeviceName, startImmediate))
    return device;

  delete device;
  return NULL;
}


PVideoOutputDevice * PVideoOutputDevice::CreateOpenedDevice(const OpenArgs & args,
                                                            bool startImmediate)
{
  OpenArgs adjustedArgs = args;
  PVideoOutputDevice * device = CreateDeviceWithDefaults<PVideoOutputDevice>(adjustedArgs.deviceName, args.driverName, NULL);
  if (device == NULL)
    return NULL;

  if (device->OpenFull(adjustedArgs, startImmediate))
    return device;

  delete device;
  return NULL;
}

#endif // P_VIDEO

// End Of File ///////////////////////////////////////////////////////////////
