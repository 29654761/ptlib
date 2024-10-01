/*
 * pprocess.h
 *
 * Operating System process (running program) class.
 *
 * Portable Windows Library
 *
 * Copyright (c) 1993-1998 Equivalence Pty. Ltd.
 *
 * Copyright (c) 1993-1999 ISDN Communications Ltd
 *
 */

#ifndef _PPROCESS

#ifndef __NUCLEUS_MNT__
#pragma interface
#endif

#include <ptlib/syncpoint.h>

PDICTIONARY(PXFdDict,    POrdinalKey, PThread);


///////////////////////////////////////////////////////////////////////////////
// PProcess

#include "../../pprocess.h"

  public:
    virtual void PXOnSignal(int);
    void         PXCheckSignals();

  protected:
    int pxSignals;
    void DoArgs(void);

#endif
