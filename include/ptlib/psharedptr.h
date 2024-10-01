/*
 * psharedptr.h
 *
 * SharedPtr template
 *
 * Portable Windows Library
 *
 * Copyright (C) 2004 Post Increment
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
 * The Initial Developer of the Original Code is Post Increment
 *
 * Contributor(s): ______________________________________.
 *
 */

#ifndef PTLIB_SHAREDPTR_H
#define PTLIB_SHAREDPTR_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif

#include <ptlib.h>
#include <memory>

#if __cplusplus < 201103L

/**
 *
 * These templates implement an pointner class with an integral reference count
 * based on the PContainer base class. This allows the easy creation of an
 * a reference counted ptr that will autodestruct when the last reference 
 * goes out of scope.
 */

template <class T>
class PSharedPtr : public PContainer
{
  PCLASSINFO(PSharedPtr, PContainer);
  public:
    typedef T element_type;

    PSharedPtr(element_type * p = NULL)
    { ptr = p; }

    PSharedPtr(const PSharedPtr & c)
      : PContainer(c)
    { CopyContents(c); } 

    PSharedPtr(std::auto_ptr<element_type> & v)
    { ptr = v.release(); }

    PSharedPtr & operator=(const PSharedPtr & c) 
    { AssignContents(c); return *this; } 

    virtual ~PSharedPtr()
    { Destruct(); } 

    virtual PBoolean MakeUnique() 
    { if (PContainer::MakeUnique()) return true; CloneContents(this); return false; } 

    PBoolean SetSize(PINDEX)
    { return false; }

    element_type * get() const
    { return ptr; }

    P_DEPRECATED element_type * Get() const
    { return ptr; }

    void reset(element_type * p = NULL)
    { AssignContents(PSharedPtr(p)); }

    P_DEPRECATED void Reset()
    { AssignContents(PSharedPtr()); }

    element_type & operator*() const
    { return *ptr; }

    element_type * operator->() const
    { return ptr; }


  protected: 
    PSharedPtr(int dummy, const PSharedPtr * c)
    : PContainer(dummy, c)
    { CloneContents(c); } 

    void AssignContents(const PContainer & c) 
    { PContainer::AssignContents(c); CopyContents((const PSharedPtr &)c); }

    void DestroyContents()
    { delete(ptr); }

    void CloneContents(const PContainer * src)
    { ptr = ((const PSharedPtr *)src)->ptr; }

    void CopyContents(const PContainer & c)
    { ptr = ((const PSharedPtr &)c).ptr; }

  protected:
    element_type * ptr;
};


#else // __cplusplus

template <typename T> using PSharedPtr = std::shared_ptr<T>;

#endif // __cplusplus

#endif // PTLIB_SHAREDPTR_H


// End Of File ///////////////////////////////////////////////////////////////
