/*
 * ptts.cxx
 *
 * Text To Speech classes
 *
 * Portable Windows Library
 *
 * Copyright (c) 2002 Equivalence Pty. Ltd.
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
#pragma implementation "ptts.h"
#endif

#include <ptlib.h>

#if P_TTS && P_SAPI

#include <ptclib/ptts.h>
#include <ptlib/msos/ptlib/pt_atl.h>


////////////////////////////////////////////////////////////
//
// Text to speech using Microsoft's Speech API (SAPI)

#ifdef _MSC_VER
  #pragma comment(lib, "sapi.lib")
#endif

#include <sphelper.h>


class PTextToSpeech_SAPI : public PTextToSpeech
{
    PCLASSINFO(PTextToSpeech_SAPI, PTextToSpeech);
  public:
    PTextToSpeech_SAPI();
    ~PTextToSpeech_SAPI();

    // overrides
    PStringArray GetVoiceList();
    PBoolean SetVoice(const PString & voice);

    PBoolean SetSampleRate(unsigned rate);
    unsigned GetSampleRate();

    PBoolean SetChannels(unsigned channels);
    unsigned GetChannels();

    PBoolean SetVolume(unsigned volume);
    unsigned GetVolume();

    PBoolean OpenFile(const PFilePath & fn);
    PBoolean OpenChannel(PChannel * channel);
    PBoolean IsOpen()     { return m_opened; }

    PBoolean Close();
    PBoolean Speak(const PString & str, TextType hint);

  protected:
    CComPtr<ISpVoice>  m_cpVoice;
    CComPtr<ISpStream> m_cpWavStream;
    bool               m_opened;
    SPSTREAMFORMAT     m_spsfFormat;
    PString            m_CurrentVoice;
};

PFACTORY_CREATE(PFactory<PTextToSpeech>, PTextToSpeech_SAPI, "Microsoft SAPI", false);


#define new PNEW
#define PTraceModule() "SAPI-TTS"

PTextToSpeech_SAPI::PTextToSpeech_SAPI()
  : m_opened(false)
  , m_spsfFormat(SPSF_8kHz16BitMono)
{
  PThread::Current()->CoInitialise();
  PTRACE(4, "Constructed " << this);
}


PTextToSpeech_SAPI::~PTextToSpeech_SAPI()
{
  PTRACE(4, "Destroyed " << this);
}


PBoolean PTextToSpeech_SAPI::OpenChannel(PChannel *)
{
  Close();
  return false;
}


PBoolean PTextToSpeech_SAPI::OpenFile(const PFilePath & fn)
{
  Close();

  PComResult hr = m_cpVoice.CoCreateInstance(CLSID_SpVoice);
  if (hr.Failed()) {
    PTRACE(2, "Could not start SAPI: " << hr);
    return false;
  }

  CSpStreamFormat wavFormat;
  wavFormat.AssignFormat(m_spsfFormat);

  PWideString wfn = fn;
  hr = SPBindToFile(wfn, SPFM_CREATE_ALWAYS, &m_cpWavStream, &wavFormat.FormatId(), wavFormat.WaveFormatExPtr()); 
  if (hr.Failed()) {
    m_cpWavStream.Release();
    return false;
  }

  hr = m_cpVoice->SetOutput(m_cpWavStream, true);
  m_opened = hr.Succeeded();
  return m_opened;
}


PBoolean PTextToSpeech_SAPI::Close()
{
  if (!m_opened)
    return false;

  m_cpVoice->WaitUntilDone(INFINITE);
  m_cpWavStream.Release();
  m_cpVoice.Release();

  m_opened = false;
  return true;
}


PBoolean PTextToSpeech_SAPI::Speak(const PString & text, TextType hint)
{
  if (!IsOpen())
    return false;

  PWideString wtext = text;

  // do various things to the string, depending upon the hint
  switch (hint) {
    case Digits:
      break;
    default:
      break;
  };

  if (m_CurrentVoice != NULL && !m_CurrentVoice.IsEmpty()) {
    PTRACE(4, "Trying to set voice \"" << m_CurrentVoice << "\""
              " of voices: " << setfill(',') << GetVoiceList());

    //Enumerate voice tokens with attribute "Name=<specified voice>"
    CComPtr<IEnumSpObjectTokens> cpEnum;
    if (PCOM_SUCCEEDED(SpEnumTokens,(SPCAT_VOICES, m_CurrentVoice.AsWide(), NULL, &cpEnum))) {
      //Get the closest token
      CComPtr<ISpObjectToken> cpVoiceToken;
      if (PCOM_SUCCEEDED(cpEnum->Next,(1, &cpVoiceToken, NULL))) {
        //set the voice
        if (PCOM_SUCCEEDED(m_cpVoice->SetVoice,(cpVoiceToken))) {
          PTRACE(4, "SetVoice(" << m_CurrentVoice << ") OK!");
        }
      }
    } 
  }

  PTRACE(4, "Speaking...");
  return PCOM_SUCCEEDED(m_cpVoice->Speak,(wtext, SPF_DEFAULT, NULL));
}


PStringArray PTextToSpeech_SAPI::GetVoiceList()
{
  //Enumerate the available voices 
  PStringArray voiceList;

  CComPtr<IEnumSpObjectTokens> cpEnum;
  ULONG ulCount = 0;
  PComResult hr;

  // Get the number of voices
  if (PCOM_SUCCEEDED_EX(hr,SpEnumTokens,(SPCAT_VOICES, NULL, NULL, &cpEnum))) {
    if (PCOM_SUCCEEDED_EX(hr,cpEnum->GetCount,(&ulCount))) {
      PTRACE(4, "Found " << ulCount << " voices..");

      // Obtain a list of available voice tokens, set the voice to the token, and call Speak
      while (ulCount-- > 0) {
        CComPtr<ISpObjectToken> cpVoiceToken;
        if (hr.Succeeded(cpEnum->Next(1, &cpVoiceToken, NULL))) {
          PWSTR pDescription = NULL;
          SpGetDescription(cpVoiceToken, &pDescription);
          PWideString desc(pDescription);
          CoTaskMemFree(pDescription);
          voiceList.AppendString(desc);
          PTRACE(4, "Found voice: " << desc);
        }
      } 
    }
  }

  return voiceList;
}


PBoolean PTextToSpeech_SAPI::SetVoice(const PString & voice)
{
  m_CurrentVoice = voice;
  return true;
}


PBoolean PTextToSpeech_SAPI::SetSampleRate(unsigned rate)
{
  switch (rate) {
    case 8000 :
      m_spsfFormat = GetChannels() > 1 ? SPSF_8kHz16BitStereo : SPSF_8kHz16BitMono;
      return true;
    case 11000 :
    case 11025 :
      m_spsfFormat = GetChannels() > 1 ? SPSF_11kHz16BitStereo : SPSF_11kHz16BitMono;
      return true;
    case 12000 :
      m_spsfFormat = GetChannels() > 1 ? SPSF_12kHz16BitStereo : SPSF_12kHz16BitMono;
      return true;
    case 16000 :
      m_spsfFormat = GetChannels() > 1 ? SPSF_16kHz16BitStereo : SPSF_16kHz16BitMono;
      return true;
    case 22000 :
    case 22050 :
      m_spsfFormat = GetChannels() > 1 ? SPSF_22kHz16BitStereo : SPSF_22kHz16BitMono;
      return true;
    case 24000 :
      m_spsfFormat = GetChannels() > 1 ? SPSF_24kHz16BitStereo : SPSF_24kHz16BitMono;
      return true;
    case 32000 :
      m_spsfFormat = GetChannels() > 1 ? SPSF_32kHz16BitStereo : SPSF_32kHz16BitMono;
      return true;
    case 44000 :
    case 44100 :
      m_spsfFormat = GetChannels() > 1 ? SPSF_44kHz16BitStereo : SPSF_44kHz16BitMono;
      return true;
    case 48000 :
      m_spsfFormat = GetChannels() > 1 ? SPSF_8kHz16BitStereo : SPSF_48kHz16BitMono;
      return true;
  }
  return false;
}

unsigned PTextToSpeech_SAPI::GetSampleRate()
{
  switch (m_spsfFormat) {
    case SPSF_8kHz16BitMono :
    case SPSF_8kHz16BitStereo :
      return 8000;
    case SPSF_11kHz16BitMono :
    case SPSF_11kHz16BitStereo :
      return 11025;
    case SPSF_12kHz16BitMono :
    case SPSF_12kHz16BitStereo :
      return 12000;
    case SPSF_16kHz16BitMono :
    case SPSF_16kHz16BitStereo :
      return 16000;
    case SPSF_22kHz16BitMono :
    case SPSF_22kHz16BitStereo :
      return 22050;
    case SPSF_24kHz16BitMono :
    case SPSF_24kHz16BitStereo :
      return 24000;
    case SPSF_32kHz16BitMono :
    case SPSF_32kHz16BitStereo :
      return 32000;
    case SPSF_44kHz16BitMono :
    case SPSF_44kHz16BitStereo :
      return 44100;
    case SPSF_48kHz16BitMono :
    case SPSF_48kHz16BitStereo :
      return 48000;
  }
  return 0;
}

PBoolean PTextToSpeech_SAPI::SetChannels(unsigned channels)
{
  switch (channels) {
    case 1:
      switch (m_spsfFormat) {
        case SPSF_8kHz16BitMono :
        case SPSF_11kHz16BitMono :
        case SPSF_12kHz16BitMono :
        case SPSF_16kHz16BitMono :
        case SPSF_22kHz16BitMono :
        case SPSF_24kHz16BitMono :
        case SPSF_32kHz16BitMono :
        case SPSF_44kHz16BitMono :
        case SPSF_48kHz16BitMono :
          return true;
        case SPSF_8kHz16BitStereo :
          m_spsfFormat = SPSF_8kHz16BitMono;
          return true;
        case SPSF_11kHz16BitStereo :
          m_spsfFormat = SPSF_11kHz16BitMono;
          return true;
        case SPSF_12kHz16BitStereo :
          m_spsfFormat = SPSF_12kHz16BitMono;
          return true;
        case SPSF_16kHz16BitStereo :
          m_spsfFormat = SPSF_16kHz16BitMono;
          return true;
        case SPSF_22kHz16BitStereo :
          m_spsfFormat = SPSF_22kHz16BitMono;
          return true;
        case SPSF_24kHz16BitStereo :
          m_spsfFormat = SPSF_24kHz16BitMono;
          return true;
        case SPSF_32kHz16BitStereo :
          m_spsfFormat = SPSF_16kHz16BitMono;
          return true;
        case SPSF_44kHz16BitStereo :
          m_spsfFormat = SPSF_44kHz16BitMono;
          return true;
        case SPSF_48kHz16BitStereo :
          m_spsfFormat = SPSF_48kHz16BitMono;
          return true;
      }
      break;

    case 2:
      switch (m_spsfFormat) {
        case SPSF_8kHz16BitMono :
          m_spsfFormat = SPSF_8kHz16BitStereo;
          return true;
        case SPSF_11kHz16BitMono :
          m_spsfFormat = SPSF_11kHz16BitStereo;
          return true;
        case SPSF_12kHz16BitMono :
          m_spsfFormat = SPSF_12kHz16BitStereo;
          return true;
        case SPSF_16kHz16BitMono :
          m_spsfFormat = SPSF_16kHz16BitStereo;
          return true;
        case SPSF_22kHz16BitMono :
          m_spsfFormat = SPSF_22kHz16BitStereo;
          return true;
        case SPSF_24kHz16BitMono :
          m_spsfFormat = SPSF_24kHz16BitStereo;
          return true;
        case SPSF_32kHz16BitMono :
          m_spsfFormat = SPSF_32kHz16BitStereo;
          return true;
        case SPSF_44kHz16BitMono :
          m_spsfFormat = SPSF_44kHz16BitStereo;
          return true;
        case SPSF_48kHz16BitMono :
          m_spsfFormat = SPSF_48kHz16BitStereo;
          return true;
        case SPSF_8kHz16BitStereo :
        case SPSF_11kHz16BitStereo :
        case SPSF_12kHz16BitStereo :
        case SPSF_16kHz16BitStereo :
        case SPSF_22kHz16BitStereo :
        case SPSF_24kHz16BitStereo :
        case SPSF_32kHz16BitStereo :
        case SPSF_44kHz16BitStereo :
        case SPSF_48kHz16BitStereo :
          return true;
      }
  }
  return false;
}

unsigned PTextToSpeech_SAPI::GetChannels()
{
  switch (m_spsfFormat) {
    case SPSF_8kHz16BitMono :
    case SPSF_11kHz16BitMono :
    case SPSF_12kHz16BitMono :
    case SPSF_16kHz16BitMono :
    case SPSF_22kHz16BitMono :
    case SPSF_24kHz16BitMono :
    case SPSF_32kHz16BitMono :
    case SPSF_44kHz16BitMono :
    case SPSF_48kHz16BitMono :
      return 1;
    case SPSF_8kHz16BitStereo :
    case SPSF_11kHz16BitStereo :
    case SPSF_12kHz16BitStereo :
    case SPSF_16kHz16BitStereo :
    case SPSF_22kHz16BitStereo :
    case SPSF_24kHz16BitStereo :
    case SPSF_32kHz16BitStereo :
    case SPSF_44kHz16BitStereo :
    case SPSF_48kHz16BitStereo :
      return 2;
  }
  return 0;
}

PBoolean PTextToSpeech_SAPI::SetVolume(unsigned)
{
  return false;
}

unsigned PTextToSpeech_SAPI::GetVolume()
{
  return 0;
}

#endif // P_TTS && P_SAPI
