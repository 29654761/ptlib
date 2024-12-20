/*
 * osutil.cxx
 *
 * Operating System classes implementation
 *
 * Portable Windows Library
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

#define _OSUTIL_CXX

#pragma implementation "timer.h"
#pragma implementation "pdirect.h"
#pragma implementation "file.h"
#pragma implementation "textfile.h"
#pragma implementation "conchan.h"
#pragma implementation "ptime.h"
#pragma implementation "timeint.h"
#pragma implementation "filepath.h"
#pragma implementation "lists.h"
#pragma implementation "pstring.h"
#pragma implementation "dict.h"
#pragma implementation "array.h"
#pragma implementation "object.h"
#pragma implementation "contain.h"

#if defined(P_LINUX) || defined(P_GNU_HURD)
#ifndef _REENTRANT
#define _REENTRANT
#endif
#elif defined(P_SOLARIS)
#define _POSIX_PTHREAD_SEMANTICS
#endif

#include <ptlib.h>


#include <fcntl.h>
#ifdef P_VXWORKS
#include <sys/times.h>
#else
#include <time.h>
#include <sys/time.h>
#include <termios.h>
#endif
#include <ctype.h>

#if P_CURSES==1
  #include <ncurses.h>
#endif

#if defined(P_LINUX) || defined(P_GNU_HURD)

#include <mntent.h>
#include <sys/vfs.h>

#if __GNUC__ < 3 || (__GNUC__ == 3 && __GNUC_MINOR__ < 7)
#include <localeinfo.h>
#else
#define P_USE_LANGINFO
#endif

#elif defined(P_ANDROID)

#include <mntent.h>
#include <sys/vfs.h>
#define P_USE_STRFTIME

#elif defined(P_FREEBSD) || defined(P_OPENBSD) || defined(P_NETBSD) || defined(P_MACOSX) || defined(P_IOS)
#define P_USE_STRFTIME

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/timeb.h>

#if defined(P_NETBSD)
#include <sys/statvfs.h>
#define statfs statvfs
#endif

#elif defined(P_HPUX9) 
#define P_USE_LANGINFO

#elif defined(P_AIX)
#define P_USE_STRFTIME

#include <fstab.h>
#include <sys/stat.h>

#elif defined(P_SOLARIS) 
#define P_USE_LANGINFO
#include <sys/timeb.h>
#include <sys/statvfs.h>
#include <sys/mnttab.h>

#elif defined(P_SUN4)
#include <sys/timeb.h>

#elif defined(__BEOS__)
#define P_USE_STRFTIME

#elif defined(P_IRIX)
#define P_USE_LANGINFO
#include <sys/stat.h>
#include <sys/statfs.h>
#include <stdio.h>
#include <mntent.h>

#elif defined(P_VXWORKS)
#define P_USE_STRFTIME

#elif defined(P_RTEMS)
#define P_USE_STRFTIME
#include <time.h>
#include <stdio.h>
#define random() rand()
#define srandom(a) srand(a)

#elif defined(P_QNX)
#include <sys/dcmd_blk.h>
#include <sys/statvfs.h>
#define P_USE_STRFTIME
#endif

#ifdef P_USE_LANGINFO
#include <langinfo.h>
#endif

#if defined(P_MACOSX) || defined(P_IOS)
  #include <mach/mach_time.h>
#endif

#if HAVE_IOCTL_H
  #include <ioctl.h>
#elif HAVE_SYS_IOCTL_H
  #include <sys/ioctl.h>
#endif


#define  LINE_SIZE_STEP  100

#define  DEFAULT_FILE_MODE  (S_IRUSR|S_IWUSR|S_IROTH|S_IRGRP)

#include <ptlib/pprocess.h>

#if !P_USE_INLINES
#include "ptlib/osutil.inl"
#ifdef _WIN32
#include "ptlib/win32/ptlib/ptlib.inl"
#else
#include "ptlib/unix/ptlib/ptlib.inl"
#endif
#endif

#ifdef P_SUN4
extern "C" {
int on_exit(void (*f)(void), caddr_t);
int atexit(void (*f)(void))
{
  return on_exit(f, 0);
}
static char *tzname[2] = { "STD", "DST" };
};
#endif

#define new PNEW

#if defined(__arm__) && !defined(__llvm__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 6))

// ARM build doesn't link before GCC v4.6
// This code mostly, and shamelessly, stolen from 4.6 source

typedef int (*__kernel_cmpxchg64_t)(const uint64_t * oldval,
                                    const uint64_t * newval,
                                    volatile void * ptr);

static int dummy_cmpxchg64(const uint64_t *,
                           const uint64_t * newval,
                           volatile void * ptr)
{
  // Do it without memory barrier
  *(uint64_t *)ptr = *newval;
  return 0;
}

static __kernel_cmpxchg64_t get_kernel_cmpxchg64()
{
  if (*(unsigned int *)0xffff0ffc >= 5) // kernel_helper_version
    return (__kernel_cmpxchg64_t)0xffff0f60;

  static const char err[] = "WARNING: __kernel_cmpxchg64 helper not in kernel, no 64 bit atomic operations.\n";
  if (write(2, err, sizeof(err)-1) != sizeof(err) - 1)
    abort();
  return dummy_cmpxchg64;
}

extern "C" {
  uint64_t __sync_lock_test_and_set_8(volatile void * ptr, uint64_t val)
  {
    static __kernel_cmpxchg64_t kernel_cmpxchg64 = get_kernel_cmpxchg64();

    int failure;
    uint64_t oldval;

    do {
      oldval = *(uint64_t *)ptr;
      failure = kernel_cmpxchg64(&oldval, &val, ptr);
    } while (failure != 0);

    return oldval;
  }

  uint64_t __sync_add_and_fetch_8(volatile void * ptr, uint64_t val)
  {
    static __kernel_cmpxchg64_t kernel_cmpxchg64 = get_kernel_cmpxchg64();

    int failure;
    uint64_t tmp1,tmp2;

    do {
      tmp1 = *(uint64_t *)ptr;
      tmp2 = tmp1 + val;
      failure = kernel_cmpxchg64(&tmp1, &tmp2, ptr);
    } while (failure != 0);

    return tmp2;
  }
};
#endif

int PX_NewHandle(const char * clsName, int fd)
{
#if PTRACING
  if (fd < 0 || !PProcess::IsInitialised())
    return fd;

#if PTRACING
  static PCriticalSection s_waterMarkMutex;
  static int s_highWaterMark = 0;
#endif
  s_waterMarkMutex.Wait();

  bool newHigh = fd > s_highWaterMark;
  if (newHigh)
    s_highWaterMark = fd;

  s_waterMarkMutex.Signal();

  if (newHigh) {
    int maxHandles = PProcess::Current().GetMaxHandles();
    if (fd < (maxHandles - maxHandles / 20))
      PTRACE(2, "PTLib", "File handle high water mark set: " << fd << ' ' << clsName);
    else
      PTRACE(1, "PTLib", "File handle high water mark within 5% of maximum: " << fd << ' ' << clsName);
  }
#endif

  return fd;
}


static PString CanonicaliseDirectory(const PString & path)
{
  PString canonical_path;

  if (path[(PINDEX)0] == '/')
    canonical_path = '/';
  else {
    canonical_path.SetSize(P_MAX_PATH);
    PAssertOS(getcwd(canonical_path.GetPointerAndSetLength(0), canonical_path.GetSize()) != NULL);
    canonical_path.MakeMinimumSize();
    // if the path doesn't end in a slash, add one
    if (canonical_path[canonical_path.GetLength()-1] != '/')
      canonical_path += '/';
    if (path.IsEmpty() || path == ".")
      return canonical_path; // Return current directory
  }

  const char * ptr = path;
  const char * end;

  for (;;) {
    // ignore slashes
    while (*ptr == '/' && *ptr != '\0')
      ptr++;

    // finished if end of string
    if (*ptr == '\0')
      break;

    // collect non-slash characters
    end = ptr;
    while (*end != '/' && *end != '\0')
      end++;

    // make a string out of the element
    PString element(ptr, end - ptr);
    
    if (element == "..") {
      PINDEX last_char = canonical_path.GetLength()-1;
      if (last_char > 0)
        canonical_path = canonical_path.Left(canonical_path.FindLast('/', last_char-1)+1);
    }
    else if (element != "." && element != "") {
      canonical_path += element;
      canonical_path += '/';
    }
    ptr = end;
  }

  return canonical_path;
}


PFilePathString PFilePath::Canonicalise(const PFilePathString & path, bool isDirectory)
{
  if (isDirectory)
    return CanonicaliseDirectory(path);

  if (path.IsEmpty())
    return path;

  PINDEX pos;
  PString dirname;

  // if there is a slash in the string, extract the dirname
  if ((pos = path.FindLast('/')) == P_MAX_INDEX)
    pos = 0;
  else {
    dirname = path(0, pos);
    while (path[pos] == '/')
      pos++;
  }

  return CanonicaliseDirectory(dirname) + path(pos, P_MAX_INDEX);
}


///////////////////////////////////////////////////////////////////////////////
//
// timer


PTimeInterval PTimer::Tick()
{
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return PTimeInterval::NanoSeconds(ts.tv_nsec, ts.tv_sec);
#elif defined(P_MACOSX) || defined(P_IOS)
  static mach_timebase_info_data_t timebaseInfo;
  if (timebaseInfo.denom == 0) {
    mach_timebase_info(&timebaseInfo);
    timebaseInfo.denom *= 1000000; // Want milliseconds, not nanoseconds
  }
  return mach_absolute_time() * timebaseInfo.numer / timebaseInfo.denom;
#else
  #warning System does not have clock_gettime with CLOCK_MONOTONIC, using gettimeofday
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return PTimeInterval::MicroSeconds(tv.tv_usec, tv.tv_sec);
#endif // P_VXWORKS
}


///////////////////////////////////////////////////////////////////////////////
//
// PDirectory
//

void PDirectory::CopyContents(const PDirectory & d)
{
  if (d.entryInfo == NULL)
    entryInfo = NULL;
  else {
    entryInfo  = new PFileInfo;
    *entryInfo = *d.entryInfo;
  }
  directory   = NULL;
  entryBuffer = NULL;
}

void PDirectory::Close()
{
  if (directory != NULL) {
    PAssert(closedir(directory) == 0, POperatingSystemError);
    directory = NULL;
  }

  if (entryBuffer != NULL) {
    free(entryBuffer);
    entryBuffer = NULL;
  }

  if (entryInfo != NULL) {
    delete entryInfo;
    entryInfo = NULL;
  }
}

void PDirectory::Construct ()
{
  directory   = NULL;
  entryBuffer = NULL;
  entryInfo   = NULL;
}

bool PDirectory::Open(PFileInfo::FileTypes ScanMask)

{
  if (directory != NULL)
    Close();

  m_scanMask = ScanMask;

  if ((directory = opendir(theArray)) == NULL)
    return false;

  entryBuffer = (struct dirent *)malloc(sizeof(struct dirent) + P_MAX_PATH);
  entryInfo   = new PFileInfo;

  if (Next())
    return true;

  Close();
  return false;
}


bool PDirectory::Next()
{
  if (directory == NULL)
    return false;

  do {
    do {
      struct dirent * entryPtr;
      entryBuffer->d_name[0] = '\0';
#if P_HAS_POSIX_READDIR_R == 3
      if (::readdir_r(directory, entryBuffer, &entryPtr) != 0)
        return false;
      if (entryPtr != entryBuffer)
        return false;
#elif P_HAS_POSIX_READDIR_R == 2
      entryPtr = ::readdir_r(directory, entryBuffer);
      if (entryPtr == NULL)
        return false;
#else
      if ((entryPtr = ::readdir(directory)) == NULL)
        return false;
      *entryBuffer = *entryPtr;
      strcpy(entryBuffer->d_name, entryPtr->d_name);
#endif
    } while (strcmp(entryBuffer->d_name, "." ) == 0 || strcmp(entryBuffer->d_name, "..") == 0);

    /* Ignore this file if we can't get info about it */
    if (PFile::GetInfo(*this+entryBuffer->d_name, *entryInfo) == 0)
      continue;
  } while ((entryInfo->type & m_scanMask) == 0);

  return true;
}


bool PDirectory::IsSubDir() const
{
  if (entryInfo == NULL)
    return false;

  return entryInfo->type == PFileInfo::SubDirectory;
}

bool PDirectory::Restart(PFileInfo::FileTypes newScanMask)
{
  m_scanMask = newScanMask;
  if (directory != NULL)
    rewinddir(directory);
  return true;
}

PString PDirectory::GetEntryName() const
{
  if (entryBuffer == NULL)
    return PString();

  return entryBuffer->d_name;
}


bool PDirectory::GetInfo(PFileInfo & info) const
{
  if (entryInfo == NULL)
    return false;

  info = *entryInfo;
  return true;
}


bool PDirectory::Exists(const PString & p)
{
  struct stat sbuf;
  if (stat((const char *)p, &sbuf) != 0)
    return false;

  return S_ISDIR(sbuf.st_mode);
}


bool PDirectory::Remove(const PString & p)
{
  PAssert(!p.IsEmpty(), "attempt to remove dir with empty name");
  PString str = p.Left(p.GetLength()-1);
  return rmdir(str) == 0;
}

PString PDirectory::GetVolume() const
{
  PString volume;

#if defined(P_QNX)
  int fd;
  char mounton[257];

  if ((fd = open(operator+("."), O_RDONLY)) != -1) {
  mounton[256] = 0;
  devctl(fd, DCMD_FSYS_MOUNTED_ON, mounton, 256, 0);
  close(fd);
  volume = strdup(mounton);
  } 

#else
  struct stat status;
  if (stat(operator+("."), &status) != -1) {
    dev_t my_dev = status.st_dev;

#if defined(P_LINUX) || defined(P_IRIX) || defined(P_GNU_HURD) || defined(P_ANDROID)

  #if defined(P_ANDROID)
    FILE * fp = fopen("/etc/mtab", "r");
  #else
    FILE * fp = setmntent(MOUNTED, "r");
  #endif
    if (fp != NULL) {
      struct mntent * mnt;
      while ((mnt = getmntent(fp)) != NULL) {
        if (stat(mnt->mnt_dir, &status) != -1 && status.st_dev == my_dev) {
          volume = mnt->mnt_fsname;
          break;
        }
      }
    }
  #if defined(P_ANDROID)
    fclose(fp);
  #else
    endmntent(fp);
  #endif

#elif defined(P_SOLARIS)

    FILE * fp = fopen("/etc/mnttab", "r");
    if (fp != NULL) {
      struct mnttab mnt;
      while (getmntent(fp, &mnt) == 0) {
        if (stat(mnt.mnt_mountp, &status) != -1 && status.st_dev == my_dev) {
          volume = mnt.mnt_special;
          break;
        }
      }
    }
    fclose(fp);

#elif defined(P_FREEBSD) || defined(P_OPENBSD) || defined(P_NETBSD) || defined(P_MACOSX) || defined(P_IOS)

    struct statfs * mnt;
    int count = getmntinfo(&mnt, MNT_NOWAIT);
    for (int i = 0; i < count; i++) {
      if (stat(mnt[i].f_mntonname, &status) != -1 && status.st_dev == my_dev) {
        volume = mnt[i].f_mntfromname;
        break;
      }
    }

#elif defined (P_AIX)

    struct fstab * fs;
    setfsent();
    while ((fs = getfsent()) != NULL) {
      if (stat(fs->fs_file, &status) != -1 && status.st_dev == my_dev) {
        volume = fs->fs_spec;
        break;
      }
    }
    endfsent();

#elif defined (P_VXWORKS)

  PAssertAlways("Get Volume - not implemented for VxWorks");
  return PString::Empty();

#else
#warning Platform requires implemetation of GetVolume()

#endif
  }
#endif

  return volume;
}

bool PDirectory::GetVolumeSpace(PInt64 & total, PInt64 & free, DWORD & clusterSize) const
{
#if defined(P_LINUX) || defined(P_FREEBSD) || defined(P_OPENBSD) || defined(P_NETBSD) || defined(P_MACOSX) || defined(P_IOS) || defined(P_GNU_HURD) || defined(P_ANDROID)

  struct statfs fs;

  if (statfs(operator+("."), &fs) == -1)
    return false;

  clusterSize = fs.f_bsize;
  total = fs.f_blocks*(PInt64)fs.f_bsize;
  free = fs.f_bavail*(PInt64)fs.f_bsize;
  return true;

#elif defined(P_AIX) || defined(P_VXWORKS)

  struct statfs fs;
  if (statfs((char *) ((const char *)operator+(".") ), &fs) == -1)
    return false;

  clusterSize = fs.f_bsize;
  total = fs.f_blocks*(PInt64)fs.f_bsize;
  free = fs.f_bavail*(PInt64)fs.f_bsize;
  return true;

#elif defined(P_SOLARIS)

  struct statvfs buf;
  if (statvfs(operator+("."), &buf) != 0)
    return false;

  clusterSize = buf.f_frsize;
  total = buf.f_blocks * buf.f_frsize;
  free  = buf.f_bfree  * buf.f_frsize;

  return true;
  
#elif defined(P_IRIX)

  struct statfs fs;

  if (statfs(operator+("."), &fs, sizeof(struct statfs), 0) == -1)
    return false;

  clusterSize = fs.f_bsize;
  total = fs.f_blocks*(PInt64)fs.f_bsize;
  free = fs.f_bfree*(PInt64)fs.f_bsize;
  return true;

#elif defined(P_QNX)

  struct statvfs fs;

  if (statvfs(operator+("."), &fs) == -1)
    return false;

  clusterSize = fs.f_bsize;
  total = fs.f_blocks*(PInt64)fs.f_bsize;
  free = fs.f_bavail*(PInt64)fs.f_bsize;
  return true;

#else

#warning Platform requires implemetation of GetVolumeSpace()
  return false;

#endif
}

PDirectory PDirectory::GetParent() const
{
  if (IsRoot())
    return *this;
  
  return *this + "..";
}

PStringArray PDirectory::GetPath() const
{
  PStringArray path;

  if (IsEmpty())
    return path;

  PStringArray tokens = Tokenise("/");

  path.SetSize(tokens.GetSize()+1);

  PINDEX count = 1; // First path field is volume name, empty under unix
  for (PINDEX i = 0; i < tokens.GetSize(); i++) {
    if (!tokens[i].IsEmpty())
     path[count++] = tokens[i];
  }

  path.SetSize(count);

  return path;
}


///////////////////////////////////////////////////////////////////////////////
//
// PFile
//

bool PFile::InternalOpen(OpenMode mode, OpenOptions opt, PFileInfo::Permissions permissions)
{
  Close();
  clear();

  if (opt != ModeDefault)
    m_removeOnClose = opt & Temporary;

  if (m_path.IsEmpty()) {
    m_path = PDirectory::GetTemporary() + "PTLXXXXXX";
#ifndef P_VXWORKS
#ifdef P_RTEMS
    _reent _reent_data;
    memset(&_reent_data, 0, sizeof(_reent_data));
    os_handle = _mkstemp_r(&_reent_data, m_path.GetPointerAndSetLength(m_path.GetLength())); // Shouldn't change length
#else
    os_handle = mkstemp(m_path.GetPointerAndSetLength(m_path.GetLength())); // Shouldn't change length
#endif // P_RTEMS
    if (!ConvertOSError(os_handle))
      return false;
  } else {
#else
    static int number = 0;
    sprintf(templateStr+3, "%06d", number++);
    path = templateStr;
  }
  {
#endif // !P_VXWORKS
    int oflags = 0;
    switch (mode) {
      case ReadOnly :
        oflags |= O_RDONLY;
        if (opt == ModeDefault)
          opt = MustExist;
        break;
      case WriteOnly :
        oflags |= O_WRONLY;
        if (opt == ModeDefault)
          opt = Create|Truncate;
        break;
      case ReadWrite :
        oflags |= O_RDWR;
        if (opt == ModeDefault)
          opt = Create;
        break;
  
      default :
        PAssertAlways(PInvalidParameter);
    }
    if (opt & Create)
      oflags |= O_CREAT;
    if (opt & Exclusive)
      oflags |= O_EXCL;
    if (opt & Truncate)
      oflags |= O_TRUNC;

    // We really want the permissions we specify
    mode_t oldMask = umask(0);
    int h = ::open(m_path, oflags, permissions.AsBits());
    umask(oldMask);
    if (!ConvertOSError(os_handle = PX_NewHandle(GetClass(), h)))
      return false;
  }

#ifndef P_VXWORKS
  return ConvertOSError(::fcntl(os_handle, F_SETFD, 1));
#else
  return true;
#endif
}


PBoolean PFile::SetLength(off_t len)
{
  return ConvertOSError(ftruncate(GetHandle(), len));
}


bool PFile::Exists(const PFilePath & name)
{ 
#ifdef P_VXWORKS
  // access function not defined for VxWorks
  // as workaround, open the file in read-only mode
  // if it succeeds, the file exists
  PFile file(name, ReadOnly, MustExist);
  PBoolean exists = file.IsOpen();
  if(exists == true)
    file.Close();
  return exists;
#else
  return access(name, 0) == 0; 
#endif // P_VXWORKS
}


bool PFile::Access(const PFilePath & name, OpenMode mode)
{
#ifdef P_VXWORKS
  // access function not defined for VxWorks
  // as workaround, open the file in specified mode
  // if it succeeds, the access is allowed
  PFile file(name, mode, ModeDefault);
  PBoolean access = file.IsOpen();
  if(access == true)
    file.Close();
  return access;
#else  
  int accmode;

  switch (mode) {
    case ReadOnly :
      accmode = R_OK;
      break;

    case WriteOnly :
      accmode = W_OK;
      break;

    default :
      accmode = R_OK | W_OK;
  }

  return access(name, accmode) == 0;
#endif // P_VXWORKS
}


bool PFile::Touch(const PFilePath & name, const PTime & accessTime, const PTime & modTime)
{
  PTime now;
  P_timeval acc(accessTime.IsValid() ? accessTime : now);
  P_timeval mod(modTime.IsValid() ? modTime : now);
  timeval times[2] = { *acc, *mod };
  return utimes(name, times) == 0;
}


bool PFile::GetInfo(const PFilePath & name, PFileInfo & status)
{
  status.type = PFileInfo::UnknownFileType;

  struct stat s;
#ifdef P_VXWORKS
  if (stat(name, &s) != OK)
#else  
  if (lstat(name, &s) != 0)
#endif // P_VXWORKS
    return false;

#ifndef P_VXWORKS
  if (S_ISLNK(s.st_mode)) {
    status.type = PFileInfo::SymbolicLink;
    if (stat(name, &s) != 0) {
      status.created     = 0;
      status.modified    = 0;
      status.accessed    = 0;
      status.size        = 0;
      status.permissions = PFileInfo::AllPermissions;
      return true;
    }
  } 
  else 
#endif // !P_VXWORKS
  if (S_ISREG(s.st_mode))
    status.type = PFileInfo::RegularFile;
  else if (S_ISDIR(s.st_mode))
    status.type = PFileInfo::SubDirectory;
  else if (S_ISFIFO(s.st_mode))
    status.type = PFileInfo::Fifo;
  else if (S_ISCHR(s.st_mode))
    status.type = PFileInfo::CharDevice;
  else if (S_ISBLK(s.st_mode))
    status.type = PFileInfo::BlockDevice;
#if !defined(__BEOS__) && !defined(P_VXWORKS)
  else if (S_ISSOCK(s.st_mode))
    status.type = PFileInfo::SocketDevice;
#endif // !__BEOS__ || !P_VXWORKS

  status.created     = s.st_ctime;
  status.modified    = s.st_mtime;
  status.accessed    = s.st_atime;
  status.size        = s.st_size;
  status.permissions = PFileInfo::Permissions::FromBits(s.st_mode);

  return true;
}


bool PFile::SetPermissions(const PFilePath & name, PFileInfo::Permissions permissions)

{
  mode_t mode = 0;

    mode |= S_IROTH;
    mode |= S_IRGRP;

  if (permissions & PFileInfo::WorldExecute)
    mode |= S_IXOTH;
  if (permissions & PFileInfo::WorldWrite)
    mode |= S_IWOTH;
  if (permissions & PFileInfo::WorldRead)
    mode |= S_IROTH;

  if (permissions & PFileInfo::GroupExecute)
    mode |= S_IXGRP;
  if (permissions & PFileInfo::GroupWrite)
    mode |= S_IWGRP;
  if (permissions & PFileInfo::GroupRead)
    mode |= S_IRGRP;

  if (permissions & PFileInfo::UserExecute)
    mode |= S_IXUSR;
  if (permissions & PFileInfo::UserWrite)
    mode |= S_IWUSR;
  if (permissions & PFileInfo::UserRead)
    mode |= S_IRUSR;

#ifdef P_VXWORKS
  PFile file(name, ReadOnly, MustExist);
  if (file.IsOpen())
    return (::ioctl(file.GetHandle(), FIOATTRIBSET, mode) >= 0);

  return false;
#else  
  return chmod ((const char *)name, mode) == 0;
#endif // P_VXWORKS
}


///////////////////////////////////////////////////////////////////////////////
// PFilePath

bool PFilePath::IsValid(char c)
{
  return c != '/';
}


bool PFilePath::IsValid(const PString & str)
{
  return str.Find('/') == P_MAX_INDEX;
}


bool PFilePath::IsAbsolutePath(const PString & path)
{
  return path[(PINDEX)0] == '/';
}



///////////////////////////////////////////////////////////////////////////////
// PConsoleChannel

PConsoleChannel::PConsoleChannel()
{
}


PConsoleChannel::PConsoleChannel(ConsoleType type)
{
  Open(type);
}


PBoolean PConsoleChannel::Open(ConsoleType type)
{
  switch (type) {
    case StandardInput :
      os_handle = 0;
      return true;

    case StandardOutput :
      os_handle = 1;
      return true;

    case StandardError :
      os_handle = 2;
      return true;
  }

  return false;
}


PString PConsoleChannel::GetName() const
{
  return ttyname(os_handle);
}


PBoolean PConsoleChannel::Close()
{
  if (os_handle == 0) {
    SetLocalEcho(true);
    SetLineBuffered(true);
  }

  os_handle = -1;
  return true;
}


int PConsoleChannel::ReadChar()
{
#if P_CURSES==1
  int ch = getch();
  if (ch >= 0) {
    switch (ch) {
      case KEY_LEFT :
        return KeyLeft;
      case KEY_RIGHT :
        return KeyRight;
      case KEY_UP :
        return KeyUp;
      case KEY_DOWN :
        return KeyDown;
      case KEY_PPAGE :
        return KeyPageUp;
      case KEY_NPAGE :
        return KeyPageDown;
      case KEY_HOME :
        return KeyHome;
      case KEY_END :
        return KeyEnd;
      case KEY_BACKSPACE :
        return KeyBackSpace;
      case KEY_DC :
        return KeyDelete;
      case KEY_EIC :
        return KeyInsert;
    }

    if (ch >= KEY_F(0) && ch <= KEY_F(63))
      return ch - KEY_F0 + KeyF1;

    return ch;
  }
#endif

  return PChannel::ReadChar();
}


bool PConsoleChannel::SetLocalEcho(bool localEcho)
{
  if (CheckNotOpen())
    return false;

  if (os_handle != 0)
    return SetErrorValues(Miscellaneous, EINVAL);

#if P_CURSES==1
  if (stdscr != NULL && (localEcho ? echo() : noecho()) == OK)
    return true;
#endif

  struct termios ios;
  if (!ConvertOSError(tcgetattr(os_handle, &ios)))
    return false;

  if (((ios.c_lflag&ECHO) != 0) == localEcho)
    return true;

  if (localEcho)
    ios.c_lflag |= ECHO;
  else
    ios.c_lflag &= ~ECHO;
  return ConvertOSError(tcsetattr(os_handle, TCSANOW, &ios));
}


bool PConsoleChannel::SetLineBuffered(bool lineBuffered)
{
  if (CheckNotOpen())
    return false;

  if (os_handle != 0)
    return SetErrorValues(Miscellaneous, EINVAL);

#if P_CURSES==1
  if (stdscr != NULL && (lineBuffered ? nocbreak() : cbreak()) == OK) {
    keypad(stdscr, !lineBuffered); // Enable special keys (arrows, keypad etc)
    return true;
  }
#endif

  struct termios ios;
  if (!ConvertOSError(tcgetattr(os_handle, &ios)))
    return false;

  if (((ios.c_lflag&ICANON) != 0) == lineBuffered)
    return true;

  if (lineBuffered)
    ios.c_lflag |= ICANON;
  else
    ios.c_lflag &= ~ICANON;
  return ConvertOSError(tcsetattr(os_handle, TCSANOW, &ios));
}


bool PConsoleChannel::GetTerminalSize(unsigned & rows, unsigned & columns)
{
  if (CheckNotOpen())
    return false;

#if P_CURSES==1
  if (stdscr != NULL) {
    getmaxyx(stdscr, rows, columns);
    return rows > 0 && columns > 0;
  }
#endif

#ifdef TIOCGWINSZ
  struct winsize w;
  if (ioctl(os_handle, TIOCGWINSZ, &w) != 0)
    return false;

  rows = w.ws_row;
  columns = w.ws_col;
  return rows > 0 && columns > 0;
#else
  return false;
#endif
}


//////////////////////////////////////////////////////
//
//  PTime
//

void PTime::SetCurrentTime()
{
#ifdef P_VXWORKS
  struct timespec ts;
  clock_gettime(0,&ts);
  m_microSecondsSinceEpoch.store(ts.tv_sec*Micro + ts.tv_nsec/1000);
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  m_microSecondsSinceEpoch.store(tv.tv_sec*Micro + tv.tv_usec);
#endif // P_VXWORKS
}

const char* my_nl_langinfo(int item) {
    switch (item) {
    case 0: // Example case for LANG
        return "en_US.UTF-8";
    default:
        return "";
    }
}

PBoolean PTime::GetTimeAMPM()
{
#if defined(P_USE_LANGINFO)
  return strstr(my_nl_langinfo(T_FMT), "%p") != NULL;
#elif defined(P_USE_STRFTIME)
  char buf[30];
  struct tm t;
  memset(&t, 0, sizeof(t));
  t.tm_hour = 20;
  t.tm_min = 12;
  t.tm_sec = 11;
  strftime(buf, sizeof(buf), "%X", &t);
  return strstr(buf, "20") != NULL;
#else
#warning No AMPM implementation
  return false;
#endif
}



PString PTime::GetTimeAM()
{
#if defined(P_USE_LANGINFO)
  return PString(my_nl_langinfo(AM_STR));
#elif defined(P_USE_STRFTIME)
  char buf[30];
  struct tm t;
  memset(&t, 0, sizeof(t));
  t.tm_hour = 10;
  t.tm_min = 12;
  t.tm_sec = 11;
  strftime(buf, sizeof(buf), "%p", &t);
  return buf;
#else
#warning Using default AM string
  return "AM";
#endif
}


PString PTime::GetTimePM()
{
#if defined(P_USE_LANGINFO)
  return PString(my_nl_langinfo(PM_STR));
#elif defined(P_USE_STRFTIME)
  char buf[30];
  struct tm t;
  memset(&t, 0, sizeof(t));
  t.tm_hour = 20;
  t.tm_min = 12;
  t.tm_sec = 11;
  strftime(buf, sizeof(buf), "%p", &t);
  return buf;
#else
#warning Using default PM string
  return "PM";
#endif
}


PString PTime::GetTimeSeparator()
{
#if defined(P_LINUX) || defined(P_HPUX9) || defined(P_SOLARIS) || defined(P_IRIX) || defined(P_GNU_HURD)
#  if defined(P_USE_LANGINFO)
     const char * p = my_nl_langinfo(T_FMT);
#  elif defined(P_LINUX) || defined(P_GNU_HURD)
    const char * p = _time_info->time;
#  endif
  char buffer[2];
  while (*p == '%' || isalpha(*p))
    p++;
  buffer[0] = *p;
  buffer[1] = '\0';
  return PString(buffer);
#elif defined(P_USE_STRFTIME)
  char buf[30];
  struct tm t;
  memset(&t, 0, sizeof(t));
  t.tm_hour = 10;
  t.tm_min = 11;
  t.tm_sec = 12;
  strftime(buf, sizeof(buf), "%X", &t);
  char * sp = strstr(buf, "11") + 2;
  char * ep = sp;
  while (*ep != '\0' && !isdigit(*ep))
    ep++;
  return PString(sp, ep-sp);
#else
#warning Using default time separator
  return ":";
#endif
}

PTime::DateOrder PTime::GetDateOrder()
{
#if defined(P_USE_LANGINFO) || defined(P_LINUX) || defined(P_GNU_HURD)
#  if defined(P_USE_LANGINFO)
    const char * p = my_nl_langinfo(D_FMT);
#  else
    const char * p = _time_info->date;
#  endif

  while (*p == '%')
    p++;
  switch (tolower(*p)) {
    case 'd':
      return DayMonthYear;
    case 'y':
      return YearMonthDay;
    case 'm':
    default:
      break;
  }
  return MonthDayYear;

#elif defined(P_USE_STRFTIME)
  char buf[30];
  struct tm t;
  memset(&t, 0, sizeof(t));
  t.tm_mday = 22;
  t.tm_mon = 10;
  t.tm_year = 99;
  strftime(buf, sizeof(buf), "%x", &t);
  char * day_pos = strstr(buf, "22");
  char * mon_pos = strstr(buf, "11");
  char * yr_pos = strstr(buf, "99");
  if (yr_pos < day_pos)
    return YearMonthDay;
  if (day_pos < mon_pos)
    return DayMonthYear;
  return MonthDayYear;
#else
#warning Using default date order
  return DayMonthYear;
#endif
}

PString PTime::GetDateSeparator()
{
#if defined(P_USE_LANGINFO) || defined(P_LINUX) || defined(P_GNU_HURD)
#  if defined(P_USE_LANGINFO)
    const char * p = my_nl_langinfo(D_FMT);
#  else
    const char * p = _time_info->date;
#  endif
  char buffer[2];
  while (*p == '%' || isalpha(*p))
    p++;
  buffer[0] = *p;
  buffer[1] = '\0';
  return PString(buffer);
#elif defined(P_USE_STRFTIME)
  char buf[30];
  struct tm t;
  memset(&t, 0, sizeof(t));
  t.tm_mday = 22;
  t.tm_mon = 10;
  t.tm_year = 99;
  strftime(buf, sizeof(buf), "%x", &t);
  char * sp = strstr(buf, "22") + 2;
  char * ep = sp;
  while (*ep != '\0' && !isdigit(*ep))
    ep++;
  return PString(sp, ep-sp);
#else
#warning Using default date separator
  return "/";
#endif
}

PString PTime::GetDayName(PTime::Weekdays day, NameType type)
{
#if defined(P_USE_LANGINFO)
  return PString(
     (type == Abbreviated) ? my_nl_langinfo((nl_item)(ABDAY_1+(int)day)) :
      my_nl_langinfo((nl_item)(DAY_1+(int)day))
                );

#elif defined(P_LINUX) || defined(P_GNU_HURD)
  return (type == Abbreviated) ? PString(_time_info->abbrev_wkday[(int)day]) :
                       PString(_time_info->full_wkday[(int)day]);

#elif defined(P_USE_STRFTIME)
  char buf[30];
  struct tm t;
  memset(&t, 0, sizeof(t));
  t.tm_wday = day;
  strftime(buf, sizeof(buf), type == Abbreviated ? "%a" : "%A", &t);
  return buf;
#else
#warning Using default day names
  static char *defaultNames[] = {
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
    "Saturday"
  };

  static char *defaultAbbrev[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
  };
  return (type == Abbreviated) ? PString(defaultNames[(int)day]) :
                       PString(defaultAbbrev[(int)day]);
#endif
}

PString PTime::GetMonthName(PTime::Months month, NameType type) 
{
#if defined(P_USE_LANGINFO)
  return PString(
     (type == Abbreviated) ? my_nl_langinfo((nl_item)(ABMON_1+(int)month-1)) :
      my_nl_langinfo((nl_item)(MON_1+(int)month-1))
                );
#elif defined(P_LINUX) || defined(P_GNU_HURD)
  return (type == Abbreviated) ? PString(_time_info->abbrev_month[(int)month-1]) :
                       PString(_time_info->full_month[(int)month-1]);
#elif defined(P_USE_STRFTIME)
  char buf[30];
  struct tm t;
  memset(&t, 0, sizeof(t));
  t.tm_mon = month-1;
  strftime(buf, sizeof(buf), type == Abbreviated ? "%b" : "%B", &t);
  return buf;
#else
#warning Using default monthnames
  static char *defaultNames[] = {
  "January", "February", "March", "April", "May", "June", "July", "August",
  "September", "October", "November", "December" };

  static char *defaultAbbrev[] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
  "Sep", "Oct", "Nov", "Dec" };

  return (type == Abbreviated) ? PString(defaultNames[(int)month-1]) :
                       PString(defaultAbbrev[(int)month-1]);
#endif
}


PBoolean PTime::IsDaylightSavings()
{
  time_t theTime = ::time(NULL);
  struct tm ts;
  return os_localtime(&theTime, &ts)->tm_isdst != 0;
}

int PTime::GetTimeZone(PTime::TimeZoneType type) 
{
#if defined(P_LINUX) || defined(P_SOLARIS) || defined (P_AIX) || defined(P_IRIX) || defined(P_GNU_HURD)
  long tz = -::timezone/60;
  if (type == StandardTime)
    return tz;
  else
    return tz + ::daylight*60;
#elif defined(P_FREEBSD) || defined(P_OPENBSD) || defined(P_NETBSD) || defined(P_MACOSX) || defined(P_IOS) || defined(__BEOS__) || defined(P_QNX) || defined(P_GNU_HURD) || defined(P_ANDROID)
  time_t t;
  time(&t);
  struct tm ts;
  struct tm * tm = os_localtime(&t, &ts);
  int tz = tm->tm_gmtoff/60;
  if (type == StandardTime && tm->tm_isdst)
    return tz-60;
  if (type != StandardTime && !tm->tm_isdst)
    return tz + 60;
  return tz;
#elif defined(P_SUN4) 
  struct timeb tb;
  ftime(&tb);
  if (type == StandardTime || tb.dstflag == 0)
    return -tb.timezone;
  else
    return -tb.timezone + 60;
#else
#warning No timezone information
  return 0;
#endif
}

PString PTime::GetTimeZoneString(PTime::TimeZoneType type) 
{
#if defined(P_LINUX) || defined(P_SUN4) || defined(P_SOLARIS) || defined (P_AIX) || defined(P_IRIX) || defined(P_QNX) || defined(P_GNU)
  const char * str = (type == StandardTime) ? ::tzname[0] : ::tzname[1]; 
  if (str != NULL)
    return str;
  return PString(); 
#elif defined(P_USE_STRFTIME)
  char buf[30];
  struct tm t;
  memset(&t, 0, sizeof(t));
  t.tm_isdst = type != StandardTime;
  strftime(buf, sizeof(buf), "%Z", &t);
  return buf;
#else
#warning No timezone name information
  return PString(); 
#endif
}

// note that PX_tm is local storage inside the PTime instance

#ifdef P_PTHREADS
struct tm * PTime::os_localtime(const time_t * clock, struct tm * ts)
{
  return ::localtime_r(clock, ts);
}
#else
struct tm * PTime::os_localtime(const time_t * clock, struct tm *)
{
  return ::localtime(clock);
}
#endif

#ifdef P_PTHREADS
struct tm * PTime::os_gmtime(const time_t * clock, struct tm * ts)
{
  return ::gmtime_r(clock, ts);
}
#else
struct tm * PTime::os_gmtime(const time_t * clock, struct tm *)
{
  return ::gmtime(clock);
}
#endif

// End Of File ///////////////////////////////////////////////////////////////
