/*
 * dict.h
 *
 * Dictionary (hash table) Container classes.
 *
 * Portable Tools Library
 *
 * Copyright (c) 1993-1998 Equivalence Pty. Ltd.
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
 * Portions are Copyright (C) 1993 Free Software Foundation, Inc.
 * All Rights Reserved.
 *
 * Contributor(s): ______________________________________.
 */


#ifndef PTLIB_DICT_H
#define PTLIB_DICT_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif

#include <ptlib/array.h>

///////////////////////////////////////////////////////////////////////////////
// PDictionary classes

/**This class is used when an ordinal index value is the key for <code>PSet</code>
   and <code>PDictionary</code> classes.
 */
template <typename T>
class PKey : public PObject
{
    PCLASSINFO(PKey, PObject);
  public:
    typedef T value_type;
    typedef PKey<T> my_type;

  /**@name Construction */
  //@{
    /** Create a new key for ordinal index values.
     */
    PINLINE PKey(
      value_type newKey = 0   ///< Ordinal index value to use as a key.
    ) : m_key(newKey) { }

    /**Operator to assign the ordinal.
      */
    PINLINE PKey & operator=(value_type newKey)
    { this->m_key = newKey; return *this; }
  //@}

  /**@name Overrides from class PObject */
  //@{
    /// Create a duplicate of the PKey.
    virtual PObject * Clone() const { return new PKey(this->m_key); }

    /* Get the relative rank of the ordinal index. This is a simpel comparison
       of the objects PINDEX values.

       @return
       comparison of the two objects, <code>EqualTo</code> for same,
       <code>LessThan</code> for \p obj logically less than the
       object and <code>GreaterThan</code> for \p obj logically
       greater than the object.
     */
    virtual Comparison Compare(const PObject & obj) const
    {
      return Compare2(this->m_key, dynamic_cast<const my_type &>(obj).m_key);
    }

    /**This function calculates a hash table index value for the implementation
       of <code>PSet</code> and <code>PDictionary</code> classes.

       @return
       hash table bucket number.
     */
    virtual PINDEX HashFunction() const
    {
#if PINDEX_SIGNED
      return std::abs((PINDEX)this->m_key)%23;
#else
      return ((PINDEX)this->m_key)%23;
#endif
    }

    /**Output the ordinal index to the specified stream. This is identical to
       outputting the PINDEX, i.e. integer, value.

       @return
       stream that the index was output to.
     */
    virtual void PrintOn(ostream & strm) const { strm << this->m_key; }
  //@}

  /**@name New functions for class */
  //@{
    /** Operator so that a PKey can be used as a PINDEX value.
     */
    PINLINE operator value_type() const  { return this->m_key; }

    /**Operator to pre-increment the ordinal.
      */
    PINLINE value_type operator++() { return ++this->m_key; }

    /**Operator to post-increment the ordinal.
      */
    PINLINE value_type operator++(int) { return this->m_key++; }

    /**Operator to pre-decrement the ordinal.
      */
    PINLINE value_type operator--() { return --this->m_key; }

    /**Operator to post-decrement the ordinal.
      */
    PINLINE value_type operator--(int) { return this->m_key--; }

    /**Operator to add the ordinal.
      */
    PINLINE PKey & operator+=(value_type add) { this->m_key += add; return *this; }

    /**Operator to subtract from the ordinal.
      */
    PINLINE PKey & operator-=(value_type minus) { this->m_key -= minus; return *this; }
  //@}

  private:
    value_type m_key;
};

typedef PKey<PINDEX> POrdinalKey;


//////////////////////////////////////////////////////////////////////////////

// Member variables
struct PHashTableElement
{
    PObject           * m_key;
    PObject           * m_data;
    PHashTableElement * m_next;
    PHashTableElement * m_prev;
    PINDEX              m_bucket;

    PDECLARE_POOL_ALLOCATOR(PHashTableElement);
};

P_PUSH_MSVC_WARNINGS(26495)
struct PHashTableList
{
  PHashTableList()
    : m_head(NULL)
    , m_tail(NULL)
#if PTRACING
    , m_size(0)
#endif
  { }
  PHashTableElement * m_head;
  PHashTableElement * m_tail;
#if PTRACING
  PINDEX              m_size;
#endif
};
P_POP_MSVC_WARNINGS()
__inline std::ostream & operator<<(std::ostream & strm, const PHashTableList & hash) { return strm << (void *)hash.m_head; }

class PHashTable;


class PHashTableInfo : public PBaseArray<PHashTableList>
{
    typedef PBaseArray<PHashTableList> ParentClass;
    PCLASSINFO(PCharArray, ParentClass);
  public:
    PHashTableInfo(PINDEX initialSize = 0)
      : ParentClass(initialSize), deleteKeys(true) { }
    PHashTableInfo(PHashTableList const * buffer, PINDEX length, PBoolean dynamic = true)
      : ParentClass(buffer, length, dynamic), deleteKeys(true) { }
    virtual PObject * Clone() const { return PNEW PHashTableInfo(*this, GetSize()); }
    virtual ~PHashTableInfo() { Destruct(); }
    virtual void DestroyContents();

    void AppendElement(PObject * key, PObject * data PTRACE_PARAM(, PHashTable * owner));
    PObject * RemoveElement(const PObject & key);
    PHashTableElement * GetElementAt(PINDEX index);
    PHashTableElement * GetElementAt(const PObject & key);
    PINDEX GetElementsIndex(const PObject*obj,PBoolean byVal,PBoolean keys) const;
    PHashTableElement * NextElement(PHashTableElement * element) const;
    PHashTableElement * PrevElement(PHashTableElement * element) const;

    bool deleteKeys;
    PTRACE_THROTTLE(m_throttlePoorHashFunction, 1);

  friend class PHashTable;
  friend class PAbstractSet;
};


/**The hash table class is the basis for implementing the <code>PSet</code> and
   <code>PDictionary</code> classes.

   The hash table allows for very fast searches for an object based on a "hash
   function". This function yields an index into an array which is directly
   looked up to locate the object. When two key values have the same hash
   function value, then a linear search of a linked list is made to locate
   the object. Thus the efficiency of the hash table is highly dependent on the
   quality of the hash function for the data being used as keys.
 */
class PHashTable : public PCollection
{
  PCONTAINERINFO(PHashTable, PCollection);

  public:
  /**@name Construction */
  //@{
    /// Create a new, empty, hash table.
    PHashTable();
  //@}

  /**@name Overrides from class PObject */
  //@{
    /**Get the relative rank of the two hash tables. Actally ranking hash
       tables is really meaningless, so only equality is returned by the
       comparison. Equality is only achieved if the two instances reference the
       same hash table.

       @return
       comparison of the two objects, <code>EqualTo</code> if the same
       reference and <code>GreaterThan</code> if not.
     */
    virtual Comparison Compare(
      const PObject & obj   ///< Other PHashTable to compare against.
    ) const;
  //@}


  /**@name Overrides from class PContainer */
  //@{
    /**This function is meaningless for hash table. The size of the collection
       is determined by the addition and removal of objects. The size cannot be
       set in any other way.

       @return
       Always true.
     */
    virtual PBoolean SetSize(
      PINDEX newSize  ///< New size for the hash table, this is ignored.
    );
  //@}


  /**@name New functions for class */
  //@{
    /**Determine if the value of the object is contained in the hash table. The
       object values are compared, not the pointers.  So the objects in the
       collection must correctly implement the <code>PObject::Compare()</code>
       function. The hash table is used to locate the entry.

       @return
       true if the object value is in the set.
     */
    PINLINE PBoolean AbstractContains(
      const PObject & key   ///< Key to look for in the set.
    ) const;

    /**Get the key in the hash table at the ordinal index position.

       The ordinal position in the hash table is determined by the hash values
       of the keys and the order of insertion.

       WARNING: this code requires a linear search for every operation
                and will be VERY slow for large data sets. This function
                is kept for backwards compatibilty only. New code should
                use the iterator based access methods

       This function is primarily used by the descendent template classes, or
       macro, with the appropriate type conversion.

       @return
       reference to key at the index position.
     */
    virtual const PObject & AbstractGetKeyAt(
      PINDEX index  ///< Ordinal position in the hash table.
    ) const;

    /**Get the data in the hash table at the ordinal index position.

       The ordinal position in the hash table is determined by the hash values
       of the keys and the order of insertion.

       WARNING: this code requires a linear search for every operation
                and will be VERY slow for large data sets. This function
                is kept for backwards compatibilty only. New code should
                use the iterator based access methods

       This function is primarily used by the descendent template classes, or
       macro, with the appropriate type conversion.

       @return
       reference to key at the index position.
     */
    virtual PObject & AbstractGetDataAt(
      PINDEX index  ///< Ordinal position in the hash table.
    ) const;
  //@}

    PHashTableInfo * hashTable;
};


//////////////////////////////////////////////////////////////////////////////

/** Abstract set of PObjects.
 */
class PAbstractSet : public PHashTable
{
  PCONTAINERINFO(PAbstractSet, PHashTable);
  public:
  /**@name Construction */
  //@{
    /**Create a new, empty, set.

       Note that by default, objects placed into the list will be deleted when
       removed or when all references to the list are destroyed.
     */
    PINLINE PAbstractSet();
  //@}

  /**@name Overrides from class PCollection */
  //@{
    /**Add a new object to the collection. If the objects value is already in
       the set then the object is \b not included. If the
       <code>AllowDeleteObjects</code> option is set then the \p obj parameter
       is also deleted.

       @return
       hash function value of the newly added object.
     */
    virtual PINDEX Append(
      PObject * obj   ///< New object to place into the collection.
    );

    /**Add a new object to the collection. If the objects value is already in
       the set then the object is \b not included. If the
       <code>AllowDeleteObjects</code> option is set then the \p obj parameter is
       also deleted.

       The object is always placed in the an ordinal position dependent on its
       hash function. It is not placed at the specified position. The
       \p before parameter is ignored.

       @return
       hash function value of the newly added object.
     */
    virtual PINDEX Insert(
      const PObject & before,   ///< Object value to insert before.
      PObject * obj             ///< New object to place into the collection.
    );

    /**Add a new object to the collection. If the objects value is already in
       the set then the object is \b not included. If the
       <code>AllowDeleteObjects</code> option is set then the \p obj parameter is
       also deleted.

       The object is always placed in the an ordinal position dependent on its
       hash function. It is not placed at the specified position. The
       \p index parameter is ignored.

       @return
       hash function value of the newly added object.
     */
    virtual PINDEX InsertAt(
      PINDEX index,   ///< Index position in collection to place the object.
      PObject * obj   ///< New object to place into the collection.
    );

    /**Remove the object from the collection. If the <code>AllowDeleteObjects</code> option
       is set then the object is also deleted.

       Note that the comparison for searching for the object in collection is
       made by pointer, not by value. Thus the parameter must point to the
       same instance of the object that is in the collection.

       @return
       true if the object was in the collection.
     */
    virtual PBoolean Remove(
      const PObject * obj   ///< Existing object to remove from the collection.
    );

    /**Remove an object at the specified index. If the <code>AllowDeleteObjects</code>
       option is set then the object is also deleted.

       WARNING: this code requires a linear search for every operation
                and will be VERY slow for large data sets. This function
                is kept for backwards compatibilty only. New code should
                use the iterator based access methods

       @return
       pointer to the object being removed, or NULL if it was deleted.
     */
    virtual PObject * RemoveAt(
      PINDEX index   ///< Index position in collection to place the object.
    );

    /**This function is the same as PHashTable::AbstractGetKeyAt().

       WARNING: this code requires a linear search for every operation
                and will be VERY slow for large data sets. This function
                is kept for backwards compatibilty only. New code should
                use the iterator based access methods

       @return
       Always NULL.
     */
    virtual PObject * GetAt(
      PINDEX index  ///< Index position in the collection of the object.
    ) const;

    /**Add a new object to the collection. If the objects value is already in
       the set then the object is \b not included. If the
       AllowDeleteObjects option is set then the \p obj parameter is
       also deleted.

       The object is always placed in the an ordinal position dependent on its
       hash function. It is not placed at the specified position. The
       \p index parameter is ignored.

       @return
       true if the object was successfully added.
     */
    virtual PBoolean SetAt(
      PINDEX index,   ///< Index position in collection to set.
      PObject * val   ///< New value to place into the collection.
    );

    /**Search the collection for the specific instance of the object. The
       object pointers are compared, not the values. The hash table is used
       to locate the entry.

       Note that that will require value comparisons to be made to find the
       equivalent entry and then a final check is made with the pointers to
       see if they are the same instance.

       @return
       ordinal index position of the object, or P_MAX_INDEX .
     */
    virtual PINDEX GetObjectsIndex(
      const PObject * obj   ///< Object to find.
    ) const;

    /**Search the collection for the specified value of the object. The object
       values are compared, not the pointers.  So the objects in the
       collection must correctly implement the <code>PObject::Compare()</code>
       function. The hash table is used to locate the entry.

       @return
       ordinal index position of the object, or P_MAX_INDEX.
     */
    virtual PINDEX GetValuesIndex(
      const PObject & obj   ///< Object to find equal value.
    ) const;

    /**Calculate union of sets.
       Returns true if any new elements were added.
      */
    bool Union(
      const PAbstractSet & set
    );

    /**Calculate intersection of sets.
       Returns true if there is an intersection.
      */
    static bool Intersection(
      const PAbstractSet & set1,
      const PAbstractSet & set2,
      PAbstractSet * intersection = NULL
    );
  //@}
};


/**This template class maps the <code>PAbstractSet</code> to a specific object type. The
   functions in this class primarily do all the appropriate casting of types.

   By default, objects placed into the set will \b not be deleted when
   removed or when all references to the set are destroyed. This is different
   from the default on most collection classes.

   Note that if templates are not used the <code>PDECLARE_SET</code> macro will
   simulate the template instantiation.
 */
template <class T> class PSet : public PAbstractSet
{
  PCLASSINFO(PSet, PAbstractSet);

  public:
  /**@name Construction */
  //@{
    /**Create a new, empty, dictionary. The parameter indicates whether to
       delete objects that are removed from the set.

       Note that by default, objects placed into the set will \b not be
       deleted when removed or when all references to the set are destroyed.
       This is different from the default on most collection classes.
     */
    inline PSet(PBoolean initialDeleteObjects = false)
      : PAbstractSet() { this->AllowDeleteObjects(initialDeleteObjects); }
  //@}

  /**@name Overrides from class PObject */
  //@{
    /**Make a complete duplicate of the set. Note that all objects in the
       array are also cloned, so this will make a complete copy of the set.
     */
    virtual PObject * Clone() const
      { return PNEW PSet(0, this); }
  //@}

  /**@name New functions for class */
  //@{
    /**Include the specified object into the set. If the objects value is
       already in the set then the object is \b not included. If the
       <code>AllowDeleteObjects</code> option is set then the \p obj parameter is
       also deleted.

       The object values are compared, not the pointers.  So the objects in
       the collection must correctly implement the <code>PObject::Compare()</code>
       function. The hash table is used to locate the entry.
     */
    void Include(
      const T * obj   // New object to include in the set.
    ) { this->Append((PObject *)obj); }

    /**Include the specified objects value into the set. If the objects value
       is already in the set then the object is \b not included.

       The object values are compared, not the pointers.  So the objects in
       the collection must correctly implement the <code>PObject::Compare()</code>
       function. The hash table is used to locate the entry.
     */
    PSet & operator+=(
      const T & obj   // New object to include in the set.
    ) { this->Append(obj.Clone()); return *this; }

    /**Remove the object from the set. If the <code>AllowDeleteObjects</code> option is set
       then the object is also deleted.

       The object values are compared, not the pointers.  So the objects in
       the collection must correctly implement the <code>PObject::Compare()</code>
       function. The hash table is used to locate the entry.
     */
    void Exclude(
      const T * obj   // New object to exclude in the set.
    ) { this->Remove(obj); }

    /**Remove the objects value from the set. If the <code>AllowDeleteObjects</code>
       option is set then the object is also deleted.

       The object values are compared, not the pointers.  So the objects in
       the collection must correctly implement the <code>PObject::Compare()</code>
       function. The hash table is used to locate the entry.
     */
    PSet & operator-=(
      const T & obj   // New object to exclude in the set.
    ) { this->erase(this->find(obj)); return *this; }

    /**Determine if the value of the object is contained in the set. The
       object values are compared, not the pointers.  So the objects in the
       collection must correctly implement the <code>PObject::Compare()</code>
       function. The hash table is used to locate the entry.

       @return
       true if the object value is in the set.
     */
    PBoolean Contains(
      const T & key  ///< Key to look for in the set.
    ) const { return this->AbstractContains(key); }

    /**Determine if the value of the object is contained in the set. The
       object values are compared, not the pointers.  So the objects in the
       collection must correctly implement the <code>PObject::Compare()</code>
       function. The hash table is used to locate the entry.

       @return
       true if the object value is in the set.
     */
    PBoolean operator[](
      const T & key  ///< Key to look for in the set.
    ) const { return this->AbstractContains(key); }

    /**Get the key in the set at the ordinal index position.

       The ordinal position in the set is determined by the hash values of the
       keys and the order of insertion.

       WARNING: this code requires a linear search for every operation
                and will be VERY slow for large data sets. This function
                is kept for backwards compatibilty only. New code should
                use the iterator based access methods

       @return
       reference to key at the index position.
     */
    virtual const T & GetKeyAt(
      PINDEX index    ///< Index of value to get.
    ) const
      { return dynamic_cast<const T &>(this->AbstractGetKeyAt(index)); }
  //@}

  /**@name Iterators */
  //@{
    class iterator;
    class const_iterator;
    class iterator_base : public std::iterator<std::forward_iterator_tag, T> {
      protected:
        iterator_base()
          : table(NULL)
          , element(NULL)
          { }
        iterator_base(PHashTableInfo * t)
          : table(t)
          , element(t->GetElementAt((PINDEX)0))
          { }
        iterator_base(PHashTableInfo * t, const T & k)
          : table(t)
          , element(t->GetElementAt(k))
          { }

        PHashTableInfo    * table;
        PHashTableElement * element;

        void Next() { this->element = PAssertNULL(this->table)->NextElement(this->element); }
        void Prev() { this->element = PAssertNULL(this->table)->PrevElement(this->element); }

        T * Ptr() const { return dynamic_cast<T *>(PAssertNULL(this->element)->m_key); }

      public:
        bool operator==(const iterator_base & it) const { return this->element == it.element; }
        bool operator!=(const iterator_base & it) const { return this->element != it.element; }
    };

    class iterator : public iterator_base  {
      protected:
        iterator(PHashTableInfo * t) : iterator_base(t) { }
        iterator(PHashTableInfo * t, const T & k) : iterator_base(t, k) { }

      public:
        iterator() { }

        iterator operator++()    {                      this->Next(); return *this; }
        iterator operator--()    {                      this->Prev(); return *this; }
        iterator operator++(int) { iterator it = *this; this->Next(); return it;    }
        iterator operator--(int) { iterator it = *this; this->Prev(); return it;    }

        T * operator->() const { return  this->Ptr(); }
        T & operator* () const { return *this->Ptr(); }

      friend class PSet<T>;
    };

    iterator begin() { return iterator(this->hashTable); }
    iterator end()   { return iterator(); }
    iterator find(const T & k) { return iterator(this->hashTable, k); }


    class const_iterator : public iterator_base {
      protected:
        const_iterator(PHashTableInfo * t) : iterator_base(t) { }
        const_iterator(PHashTableInfo * t, const T & k) : iterator_base(t, k) { }

      public:
        const_iterator() { }

        const_iterator operator++()    {                            this->Next(); return *this; }
        const_iterator operator--()    {                            this->Prev(); return *this; }
        const_iterator operator++(int) { const_iterator it = *this; this->Next(); return it;    }
        const_iterator operator--(int) { const_iterator it = *this; this->Prev(); return it;    }

        const T * operator->() const { return  this->Ptr(); }
        const T & operator* () const { return *this->Ptr(); }

      friend class PSet<T>;
    };

    const_iterator begin() const { return const_iterator(this->hashTable); }
    const_iterator end()   const { return const_iterator(); }
    const_iterator find(const T & k) const { return const_iterator(this->hashTable, k); }

    void erase(const iterator & it) { this->Remove(&*it); }
    void erase(const const_iterator & it) { this->Remove(&*it); }
  //@}

  protected:
    PSet(int dummy, const PSet * c)
      : PAbstractSet(dummy, c)
      { this->reference->deleteObjects = c->reference->deleteObjects; }
};


/**Declare set class.
   This macro is used to declare a descendent of <code>PAbstractSet</code> class,
   customised for a particular object type \b T. This macro closes the
   class declaration off so no additional members can be added.

   If the compilation is using templates then this macro produces a typedef
   of the <code>PSet</code> template class.

   See the <code>PSet</code> class and <code>PDECLARE_SET</code> macro for more
   information.
 */
#define PSET(cls, T) typedef PSet<T> cls


/**Begin declaration of a set class.
   This macro is used to declare a descendent of <code>PAbstractSet</code> class,
   customised for a particular object type \b T.

   If the compilation is using templates then this macro produces a descendent
   of the <code>PSet</code> template class. If templates are not being used then the
   macro defines a set of inline functions to do all casting of types. The
   resultant classes have an identical set of functions in either case.

   See the <code>PSet</code> and <code>PAbstractSet</code> classes for more information.
 */
#define PDECLARE_SET(cls, T, initDelObj) \
  class cls : public PSet<T> { \
    typedef PSet<T> BaseClass; PCLASSINFO(cls, BaseClass) \
  protected: \
    cls(int dummy, const cls * c) \
      : BaseClass(dummy, c) { } \
  public: \
    cls(PBoolean initialDeleteObjects = initDelObj) \
      : BaseClass(initialDeleteObjects) { } \
    virtual PObject * Clone() const \
      { return PNEW cls(0, this); } \


/// A set of ordinal integers
PDECLARE_SET(POrdinalSet, POrdinalKey, true)
};

//////////////////////////////////////////////////////////////////////////////

/**An abstract dictionary container.
*/
class PAbstractDictionary : public PHashTable
{
  PCLASSINFO(PAbstractDictionary, PHashTable);
  public:
  /**@name Construction */
  //@{
    /**Create a new, empty, dictionary.

       Note that by default, objects placed into the dictionary will be deleted
       when removed or when all references to the dictionary are destroyed.
     */
    PINLINE PAbstractDictionary();
  //@}

  /**@name Overrides from class PObject */
  //@{
    /**Output the contents of the object to the stream. The exact output is
       dependent on the exact semantics of the descendent class. This is
       primarily used by the standard <code>operator<<</code> function.

       The default behaviour is to print the class name.
     */
    virtual void PrintOn(
      ostream &strm   ///< Stream to print the object into.
    ) const;
  //@}

  /**@name Overrides from class PCollection */
  //@{
    /**Insert a new object into the dictionary. The semantics of this function
       is different from that of the <code>PCollection</code> class. This function is
       exactly equivalent to the <code>SetAt()</code> function that sets a data value at
       the key value location.

       @return
       Always zero.
     */
    virtual PINDEX Insert(
      const PObject & key,   ///< Object value to use as the key.
      PObject * obj          ///< New object to place into the collection.
    );

    /**Insert a new object at the specified index. This function only applies
       to derived classes whose key is PINDEX based.

       @return
       \p index parameter.
     */
    virtual PINDEX InsertAt(
      PINDEX index,   ///< Index position in collection to place the object.
      PObject * obj   ///< New object to place into the collection.
    );

    /**Remove an object at the specified index.  This function only applies
       to derived classes whose key is PINDEX based. The returned pointer is
       then removed using the <code>SetAt()</code> function to set that key value to NULL.
       If the <code>AllowDeleteObjects</code> option is set then the object is also
       deleted.

       @return
       pointer to the object being removed, or NULL if it was deleted.
     */
    virtual PObject * RemoveAt(
      PINDEX index   ///< Index position in collection to place the object.
    );

    /**Set the object at the specified index to the new value. This function
       only applies to derived classes whose key is PINDEX based. This will
       overwrite the existing entry. If the AllowDeleteObjects() option is set
       then the old object is also deleted.

       @return
       true if the object was successfully added.
     */
    virtual PBoolean SetAt(
      PINDEX index,   ///< Index position in collection to set.
      PObject * val   ///< New value to place into the collection.
    );

    /**Get the object at the specified index position. If the index was not in
       the collection then NULL is returned.

       @return
       pointer to object at the specified index.
     */
    virtual PObject * GetAt(
      PINDEX index  ///< Index position in the collection of the object.
    ) const;

    /**Search the collection for the specific instance of the object. The
       object pointers are compared, not the values. The hash table is used
       to locate the entry.

       Note that that will require value comparisons to be made to find the
       equivalent entry and then a final check is made with the pointers to
       see if they are the same instance.

       @return
       ordinal index position of the object, or P_MAX_INDEX.
     */
    virtual PINDEX GetObjectsIndex(
      const PObject * obj  ///< Object to find.
    ) const;

    /**Search the collection for the specified value of the object. The object
       values are compared, not the pointers.  So the objects in the
       collection must correctly implement the <code>PObject::Compare()</code>
       function. The hash table is used to locate the entry.

       @return
       ordinal index position of the object, or P_MAX_INDEX.
     */
    virtual PINDEX GetValuesIndex(
      const PObject & obj  ///< Object to find value of.
    ) const;
  //@}


  /**@name New functions for class */
  //@{
    /**Set the data at the specified ordinal index position in the dictionary.

       The ordinal position in the dictionary is determined by the hash values
       of the keys and the order of insertion.

       @return
       true if the new object could be placed into the dictionary.
     */
    P_DEPRECATED virtual PBoolean SetDataAt(
      PINDEX index,   ///< Ordinal index in the dictionary.
      PObject * obj   ///< New object to put into the dictionary.
    );

    /**Add a new object to the collection. If the objects value is already in
       the dictionary then the object is overrides the previous value. If the
       AllowDeleteObjects option is set then the old object is also deleted.

       The object is placed in the an ordinal position dependent on the keys
       hash function. Subsequent searches use the hash function to speed access
       to the data item.

       @return
       true if the object was successfully added.
     */
    virtual PObject * AbstractSetAt(
      const PObject & key,  ///< Key for position in dictionary to add object.
      PObject * obj         ///< New object to put into the dictionary.
    );

    /**Get the object at the specified key position. If the key was not in the
       collection then this function asserts.

       This function is primarily for use by the operator[] function in the
       descendent template classes.

       @return
       reference to object at the specified key.
     */
    virtual PObject & GetRefAt(
      const PObject & key   ///< Key for position in dictionary to get object.
    ) const;

    /**Get the object at the specified key position. If the key was not in the
       collection then NULL is returned.

       @return
       pointer to object at the specified key.
     */
    virtual PObject * AbstractGetAt(
      const PObject & key   ///< Key for position in dictionary to get object.
    ) const;

    /**Get an array containing all the keys for the dictionary.
      */
    virtual void AbstractGetKeys(
      PArrayObjects & keys
    ) const;
  //@}

  protected:
    PINLINE PAbstractDictionary(int dummy, const PAbstractDictionary * c);

  private:
    /**This function is meaningless and will assert.

       @return
       Always zero.
     */
    virtual PINDEX Append(
      PObject * obj   ///< New object to place into the collection.
    );

    /**Remove the object from the collection. If the <code>AllowDeleteObjects</code> option
       is set then the object is also deleted.

       Note that the comparison for searching for the object in collection is
       made by pointer, not by value. Thus the parameter must point to the
       same instance of the object that is in the collection.

       @return
       true if the object was in the collection.
     */
    virtual PBoolean Remove(
      const PObject * obj   ///< Existing object to remove from the collection.
    );

};


/**This template class maps the <code>PAbstractDictionary</code> to a specific key and data
   types. The functions in this class primarily do all the appropriate casting
   of types.

   Note that if templates are not used the <code>PDECLARE_DICTIONARY</code> macro
   will simulate the template instantiation.
 */
template <class K, class D> class PDictionary : public PAbstractDictionary
{
  PCLASSINFO(PDictionary, PAbstractDictionary);

  public:
    typedef K key_type;
    typedef D data_type;
    typedef PDictionary<K, D> dict_type;

  /**@name Construction */
  //@{
    /**Create a new, empty, dictionary.

       Note that by default, objects placed into the dictionary will be
       deleted when removed or when all references to the dictionary are
       destroyed.
     */
    PDictionary()
      : PAbstractDictionary() { }
  //@}

  /**@name Overrides from class PObject */
  //@{
    /**Make a complete duplicate of the dictionary. Note that all objects in
       the array are also cloned, so this will make a complete copy of the
       dictionary.
     */
    virtual PObject * Clone() const
      { return PNEW PDictionary(0, this); }
  //@}

  /**@name New functions for class */
  //@{
    /**Get the object contained in the dictionary at the \p key
       position. The hash table is used to locate the data quickly via the
       hash function provided by the \p key.

       The last key/data pair is remembered by the class so that subseqent
       access is very fast.

       @return
       reference to the object indexed by the key.
     */
    const D & operator[](
      const K & key   ///< Key to look for in the dictionary.
    ) const { return dynamic_cast<const D &>(this->GetRefAt(key)); }
    D & operator[](
      const K & key   ///< Key to look for in the dictionary.
    ) { return dynamic_cast<D &>(this->GetRefAt(key)); }

    /**Determine if the value of the object is contained in the hash table. The
       object values are compared, not the pointers.  So the objects in the
       collection must correctly implement the <code>PObject::Compare()</code>
       function. The hash table is used to locate the entry.

       @return
       true if the object value is in the dictionary.
     */
    PBoolean Contains(
      const K & key   ///< Key to look for in the dictionary.
    ) const { return this->AbstractContains(key); }

    /**Remove an object at the specified \p key. The returned pointer is then
       removed using the <code>SetAt()</code> function to set that key value to
       NULL. If the <code>AllowDeleteObjects</code> option is set then the
       object is also deleted.

       @return
       pointer to the object being removed, or NULL if the key was not
       present in the dictionary or the object was deleted automatically.
     */
    virtual D * RemoveAt(
      const K & key   ///< Key for position in dictionary to get object.
    ) { return dynamic_cast<D *>(this->AbstractSetAt(key, NULL)); }

    /**Add a new object to the collection. If the objects value is already in
       the dictionary then the object is overrides the previous value. If the
       <code>AllowDeleteObjects</code> option is set then the old object is also deleted.

       The object is placed in the an ordinal position dependent on the keys
       hash function. Subsequent searches use the hash function to speed access
       to the data item.

       @return
       true if the object was successfully added.
     */
    virtual PBoolean SetAt(
      const K & key,  // Key for position in dictionary to add object.
      D * obj         // New object to put into the dictionary.
    ) { return this->AbstractSetAt(key, obj) != NULL; }

    /**Get the object at the specified key position. If the key was not in the
       collection then NULL is returned.

       @return
       pointer to object at the specified key.
     */
    virtual D * GetAt(
      const K & key   // Key for position in dictionary to get object.
    ) const { return dynamic_cast<D *>(this->AbstractGetAt(key)); }

    /**Get the key in the dictionary at the ordinal index position.

       The ordinal position in the dictionary is determined by the hash values
       of the keys and the order of insertion.

       WARNING: this code requires a linear search for every operation
                and will be VERY slow for large data sets. This function
                is kept for backwards compatibilty only. New code should
                use the iterator based access methods

       @return
       reference to key at the index position.
     */
    const K & GetKeyAt(
      PINDEX index  ///< Ordinal position in dictionary for key.
    ) const
      { return dynamic_cast<const K &>(this->AbstractGetKeyAt(index)); }

    /**Get the data in the dictionary at the ordinal index position.

       The ordinal position in the dictionary is determined by the hash values
       of the keys and the order of insertion.

       WARNING: this code requires a linear search for every operation
                and will be VERY slow for large data sets. This function
                is kept for backwards compatibilty only. New code should
                use the iterator based access methods

       @return
       reference to data at the index position.
     */
    D & GetDataAt(
      PINDEX index  ///< Ordinal position in dictionary for data.
    ) const
      { return dynamic_cast<D &>(this->AbstractGetDataAt(index)); }

    /**Get an array containing all the keys for the dictionary.
      */
    PArray<K> GetKeys() const
    {
      PArray<K> keys;
      this->AbstractGetKeys(keys);
      return keys;
    }
  //@}

  /**@name Iterators */
  //@{
    class iterator;
    class const_iterator;
    class iterator_base {
      protected:
        K * m_internal_first;  // Must be first two members
        D * m_internal_second;

        PHashTableInfo    * m_table;
        PHashTableElement * m_element;

        iterator_base()
          : m_internal_first(NULL)
          , m_internal_second(NULL)
          , m_table(NULL)
          , m_element(NULL)
        {
        }

        iterator_base(const dict_type * dict)
          : m_table(dict->hashTable)
        {
          this->SetElement(this->m_table->GetElementAt((PINDEX)0));
        }
        
        iterator_base(const dict_type * dict, const K & key)
          : m_table(dict->hashTable)
        {
          this->SetElement(this->m_table->GetElementAt(key));
        }

        void SetElement(PHashTableElement * element)
        {
          this->m_element = element;
          if (element != NULL) {
            this->m_internal_first  = dynamic_cast<K *>(element->m_key);
            this->m_internal_second = dynamic_cast<D *>(element->m_data);
          }
          else {
            this->m_internal_first = NULL;
            this->m_internal_second = NULL;
          }
        }

        P_PUSH_MSVC_WARNINGS(6011)
        void Next() { this->SetElement(PAssertNULL(this->m_table)->NextElement(this->m_element)); }
        void Prev() { this->SetElement(PAssertNULL(this->m_table)->PrevElement(this->m_element)); }
        P_POP_MSVC_WARNINGS()

      public:
        bool operator==(const iterator_base & it) const { return this->m_element == it.m_element; }
        bool operator!=(const iterator_base & it) const { return this->m_element != it.m_element; }
    };

    template<class CK, class CD>
    class iterator_pair {
      public:
        CK & first;
        CD & second;

      private:
        iterator_pair() : first(reinterpret_cast<CK&>(0)), second(reinterpret_cast<CD&>(0)) { }
    };

    class iterator : public iterator_base, public std::iterator<std::forward_iterator_tag, iterator_pair<K,D> > {
      protected:
        iterator(dict_type * dict) : iterator_base(dict) { }
        iterator(dict_type * dict, const K & key) : iterator_base(dict, key) { }

      public:
        iterator() { }

        iterator operator++()    {                      this->Next(); return *this; }
        iterator operator--()    {                      this->Prev(); return *this; }
        iterator operator++(int) { iterator it = *this; this->Next(); return it;    }
        iterator operator--(int) { iterator it = *this; this->Prev(); return it;    }

        typedef iterator_pair<K,D> pair;
        const pair * operator->() const { return  reinterpret_cast<const pair *>(this); }
        const pair & operator* () const { return *reinterpret_cast<const pair *>(this); }

      friend class PDictionary<K, D>;
    };

    iterator begin() { return iterator(this); }
    iterator end()   { return iterator(); }
    iterator find(const K & key) { return iterator(this, key); }


    class const_iterator : public iterator_base, public std::iterator<std::forward_iterator_tag, iterator_pair<const K,const D> > {
      protected:
        const_iterator(const dict_type * dict) : iterator_base(dict) { }
        const_iterator(const dict_type * dict, const K & key) : iterator_base(dict, key) { }

      public:
        const_iterator() { }
        const_iterator(iterator it) : iterator_base(it) { }

        const_iterator operator++()    {                            this->Next(); return *this; }
        const_iterator operator--()    {                            this->Prev(); return *this; }
        const_iterator operator++(int) { const_iterator it = *this; this->Next(); return it;    }
        const_iterator operator--(int) { const_iterator it = *this; this->Prev(); return it;    }

        typedef iterator_pair<const K, const D> pair;
        const pair * operator->() const { return  reinterpret_cast<const pair *>(this); }
        const pair & operator* () const { return *reinterpret_cast<const pair *>(this); }

      friend class PDictionary<K, D>;
    };

    const_iterator begin() const { return const_iterator(this); }
    const_iterator end()   const { return const_iterator(); }
    const_iterator find(const K & k) const { return const_iterator(this, k); }

    void erase(const       iterator & it) { this->AbstractSetAt(*it.m_element->m_key, NULL); }
    void erase(const const_iterator & it) { this->AbstractSetAt(*it.m_element->m_key, NULL); }
  //@}

  protected:
    PDictionary(int dummy, const PDictionary * c)
      : PAbstractDictionary(dummy, c) { }
};


/**Declare a dictionary class.
   This macro is used to declare a descendent of PAbstractDictionary class,
   customised for a particular key type \b K and data object type \b D.
   This macro closes the class declaration off so no additional members can
   be added.

   If the compilation is using templates then this macro produces a typedef
   of the <code>PDictionary</code> template class.

   See the <code>PDictionary</code> class and <code>PDECLARE_DICTIONARY</code> macro for
   more information.
 */
#define PDICTIONARY(cls, K, D) typedef PDictionary<K, D> cls


/**Begin declaration of dictionary class.
   This macro is used to declare a descendent of PAbstractDictionary class,
   customised for a particular key type \b K and data object type \b D.

   If the compilation is using templates then this macro produces a descendent
   of the <code>PDictionary</code> template class. If templates are not being used
   then the macro defines a set of inline functions to do all casting of types.
   The resultant classes have an identical set of functions in either case.

   See the <code>PDictionary</code> and <code>PAbstractDictionary</code> classes for more
   information.
 */
#define PDECLARE_DICTIONARY(cls, K, D) \
  PDICTIONARY(cls##_PTemplate, K, D); \
  PDECLARE_CLASS(cls, cls##_PTemplate) \
  protected: \
    cls(int dummy, const cls * c) \
      : cls##_PTemplate(dummy, c) { } \
  public: \
    cls() \
      : cls##_PTemplate() { } \
    virtual PObject * Clone() const \
      { return PNEW cls(0, this); } \


/**This template class maps the <code>PAbstractDictionary</code> to a specific key
   type and a <code>POrdinalKey</code> data type. The functions in this class
   primarily do all the appropriate casting of types.

   Note that if templates are not used the <code>PDECLARE_ORDINAL_DICTIONARY</code>
   macro will simulate the template instantiation.
 */
template <class K> class POrdinalDictionary : public PDictionary<K, POrdinalKey>
{
  typedef PDictionary<K, POrdinalKey> ParentClass;
  PCLASSINFO(POrdinalDictionary, ParentClass);

  public:
  /**@name Construction */
  //@{
    /**Create a new, empty, dictionary.

       Note that by default, objects placed into the dictionary will be
       deleted when removed or when all references to the dictionary are
       destroyed.
     */
    POrdinalDictionary()
      : ParentClass() { }
  //@}

  /**@name Overrides from class PObject */
  //@{
    /**Make a complete duplicate of the dictionary. Note that all objects in
       the array are also cloned, so this will make a complete copy of the
       dictionary.
     */
    virtual PObject * Clone() const
      { return PNEW POrdinalDictionary(0, this); }
  //@}

  /**@name New functions for class */
  //@{
    /**Get the object contained in the dictionary at the \p key
       position. The hash table is used to locate the data quickly via the
       hash function provided by the key.

       The last key/data pair is remembered by the class so that subseqent
       access is very fast.

       @return
       reference to the object indexed by the key.
     */
    PINDEX operator[](
      const K & key   // Key to look for in the dictionary.
    ) const
      { return dynamic_cast<POrdinalKey &>(this->GetRefAt(key)); }

    /**Set the data at the specified ordinal index position in the dictionary.

       The ordinal position in the dictionary is determined by the hash values
       of the keys and the order of insertion.

       WARNING: this code requires a linear search for every operation
                and will be VERY slow for large data sets. This function
                is kept for backwards compatibilty only. New code should
                use the iterator based access methods

       @return
       true if the new object could be placed into the dictionary.
     */
    virtual PBoolean SetDataAt(
      PINDEX index,   ///< Ordinal index in the dictionary.
      PINDEX ordinal  ///< New ordinal value to put into the dictionary.
    ) { return this->AbstractSetAt(this->AbstractGetKeyAt(index), PNEW POrdinalKey(ordinal)) != NULL; }

    /**Add a new object to the collection. If the objects value is already in
       the dictionary then the object is overrides the previous value. If the
       <code>AllowDeleteObjects</code> option is set then the old object is also deleted.

       The object is placed in the an ordinal position dependent on the keys
       hash function. Subsequent searches use the hash function to speed access
       to the data item.

       @return
       true if the object was successfully added.
     */
    virtual PBoolean SetAt(
      const K & key,  ///< Key for position in dictionary to add object.
      PINDEX ordinal  ///< New ordinal value to put into the dictionary.
    ) { return this->AbstractSetAt(key, PNEW POrdinalKey(ordinal)) != NULL; }

    /**Get the key in the dictionary at the ordinal index position.

       The ordinal position in the dictionary is determined by the hash values
       of the keys and the order of insertion.

       WARNING: this code requires a linear search for every operation
                and will be VERY slow for large data sets. This function
                is kept for backwards compatibilty only. New code should
                use the iterator based access methods

       @return
       reference to key at the index position.
     */
    const K & GetKeyAt(
      PINDEX index  ///< Ordinal position in dictionary for key.
    ) const
      { return dynamic_cast<const K &>(this->AbstractGetKeyAt(index)); }

    /**Get the data in the dictionary at the ordinal index position.

       The ordinal position in the dictionary is determined by the hash values
       of the keys and the order of insertion.

       The last key/data pair is remembered by the class so that subseqent
       access is very fast.

       WARNING: this code requires a linear search for every operation
                and will be VERY slow for large data sets. This function
                is kept for backwards compatibilty only. New code should
                use the iterator based access methods

       @return
       reference to data at the index position.
     */
    PINDEX GetDataAt(
      PINDEX index  ///< Ordinal position in dictionary for data.
    ) const
      { return dynamic_cast<POrdinalKey &>(this->AbstractGetDataAt(index)); }
  //@}

  protected:
    POrdinalDictionary(int dummy, const POrdinalDictionary * c)
      : ParentClass(dummy, c) { }
};


/**Declare an ordinal dictionary class.
   This macro is used to declare a descendent of PAbstractDictionary class,
   customised for a particular key type \b K and data object type of
   <code>POrdinalKey</code>. This macro closes the class declaration off so no
   additional members can be added.

   If the compilation is using templates then this macro produces a typedef
   of the <code>POrdinalDictionary</code> template class.

   See the <code>POrdinalDictionary</code> class and
   <code>PDECLARE_ORDINAL_DICTIONARY</code> macro for more information.
 */
#define PORDINAL_DICTIONARY(cls, K) typedef POrdinalDictionary<K> cls


/**Begin declaration of an ordinal dictionary class.
   This macro is used to declare a descendent of PAbstractList class,
   customised for a particular key type \b K and data object type of
   <code>POrdinalKey</code>.

   If the compilation is using templates then this macro produces a descendent
   of the <code>POrdinalDictionary</code> template class. If templates are not being
   used then the macro defines a set of inline functions to do all casting of
   types. The resultant classes have an identical set of functions in either
   case.

   See the <code>POrdinalDictionary</code> and <code>PAbstractDictionary</code> classes
   for more information.
 */
#define PDECLARE_ORDINAL_DICTIONARY(cls, K) \
  PORDINAL_DICTIONARY(cls##_PTemplate, K); \
  PDECLARE_CLASS(cls, POrdinalDictionary<K>) \
  protected: \
    cls(int dummy, const cls * c) \
      : cls##_PTemplate(dummy, c) { } \
  public: \
    cls() \
      : cls##_PTemplate() { } \
    virtual PObject * Clone() const \
      { return PNEW cls(0, this); } \


#endif // PTLIB_DICT_H

// End Of File ///////////////////////////////////////////////////////////////
