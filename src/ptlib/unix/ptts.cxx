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

#if P_TTS && P_FESTIVAL

#include <ptclib/ptts.h>

#include <festival/festival.h>


////////////////////////////////////////////////////////////
//
//  Generic text to speech using Festival
//

class PTextToSpeech_Festival : public PTextToSpeech
{
  PCLASSINFO(PTextToSpeech_Festival, PTextToSpeech);
  public:
    PTextToSpeech_Festival();
    ~PTextToSpeech_Festival();

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
    PBoolean IsOpen()    { return !m_filePath.empty(); }

    PBoolean Close();
    PBoolean Speak(const PString & str, TextType hint);

  protected:
    PDECLARE_MUTEX(m_mutex);
    unsigned  m_volume;
    unsigned  m_sampleRate;
    PFilePath m_filePath;
    EST_Wave  m_wave;
};

#define new PNEW
#define PTraceModule() "Festival-TTS"

PFACTORY_CREATE(PFactory<PTextToSpeech>, PTextToSpeech_Festival, "Festival", false);


PTextToSpeech_Festival::PTextToSpeech_Festival()
  : m_volume(100)
  , m_sampleRate(8000)
{
  PTRACE(4, "Constructed " << this);
}


PTextToSpeech_Festival::~PTextToSpeech_Festival()
{
  PWaitAndSignal mutex(m_mutex);
  Close();
  PTRACE(4, "Destroyed " << this);
}


PBoolean PTextToSpeech_Festival::OpenChannel(PChannel *)
{
  return false;
}


PBoolean PTextToSpeech_Festival::OpenFile(const PFilePath & fn)
{
  PWaitAndSignal mutex(m_mutex);

  Close();

  m_filePath = fn;
  festival_initialize(1, 10000000);
  PTRACE(4, "Opened " << m_filePath);
  return true;
}


PBoolean PTextToSpeech_Festival::Close()
{
  PWaitAndSignal mutex(m_mutex);

  if (m_filePath.empty() || m_wave.length() == 0)
    m_filePath.clear();
  else {
    m_wave.resample(m_sampleRate);
    EST_write_status result = m_wave.save(m_filePath.c_str(), "riff");

    m_filePath.clear();
    m_wave.clear();

    if (result == write_ok)
      return true;

    PTRACE(2, "WAV file write failed: code=" << result);
  }

  festival_tidy_up();
  return false;
}


PBoolean PTextToSpeech_Festival::Speak(const PString & str, TextType hint)
{
  PWaitAndSignal mutex(m_mutex);
  if (festival_text_to_wave(str.c_str(), m_wave) != 0)
    return true;

  PTRACE(2, "festival_text_to_wave() failed");
  return false;
}


PStringArray PTextToSpeech_Festival::GetVoiceList()
{
  PStringArray voiceList;
  voiceList.AppendString("default");
  return voiceList;
}


PBoolean PTextToSpeech_Festival::SetVoice(const PString & v)
{
  return v == "default";
}


PBoolean PTextToSpeech_Festival::SetSampleRate(unsigned v)
{
  m_sampleRate = v;
  return true;
}


unsigned PTextToSpeech_Festival::GetSampleRate()
{
  return m_sampleRate;
}


PBoolean PTextToSpeech_Festival::SetChannels(unsigned v)
{
  if ((unsigned)m_wave.num_channels() != v) {
    m_wave = EST_Wave(0, v, m_sampleRate);
    PTRACE(4, "Set channels to " << v << " - " << m_wave.sample_rate() << "Hz");
  }
  return v == 1;
}


unsigned PTextToSpeech_Festival::GetChannels()
{
  return m_wave.num_channels();
}


PBoolean PTextToSpeech_Festival::SetVolume(unsigned v)
{
  m_volume = v;
  return true;
}


unsigned PTextToSpeech_Festival::GetVolume()
{
  return m_volume;
}


#endif // P_TTS && P_FESTIVAL
