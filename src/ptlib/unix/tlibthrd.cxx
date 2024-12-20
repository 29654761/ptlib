/*
 * tlibthrd.cxx
 *
 * Routines for pre-emptive threading system
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

#include <sched.h>
#include <pthread.h>
#include <sys/resource.h>

#ifdef P_RTEMS
#define SUSPEND_SIG SIGALRM
#include <sched.h>
#else
#define SUSPEND_SIG SIGVTALRM
#endif

#if defined(P_MACOSX)
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#elif defined(P_LINUX)
#include <sys/syscall.h>
#elif defined(P_ANDROID)
#include <asm/page.h>
#include <jni.h>
#endif

#ifndef P_ANDROID
  #define P_USE_THREAD_CANCEL 1
#else
  //static JavaVM * AndroidJavaVM;
  //JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
  //{
  //  AndroidJavaVM = vm;
  //  return JNI_VERSION_1_6;
  //}
#endif


static PINDEX const PThreadMinimumStack = 16*PTHREAD_STACK_MIN; // Set a decent stack size that won't eat all virtual memory, or crash


int PX_NewHandle(const char *, int);


#define PAssertWithRetry(func, arg, ...) \
  { \
    unsigned threadOpRetry = 0; \
    while (PAssertThreadOp(func(arg, ##__VA_ARGS__), threadOpRetry, #func, \
              reinterpret_cast<const void *>(arg), PDebugLocation(__FILE__, __LINE__, __FUNCTION__))); \
  }


static bool PAssertThreadOp(int retval,
                            unsigned & retry,
                            const char * funcname,
                            const void * arg1,
                            const PDebugLocation & location)
{
  if (retval == 0) {
#if PTRACING
    if (PTrace::CanTrace(2) && retry > 0)
      PTrace::Begin(2, location.m_file, location.m_line, NULL, "PTLib")
          << funcname << '(' << arg1 << ") required " << retry << " retries!" << PTrace::End;
#endif
    return false;
  }

  int err = retval < 0 ? errno : retval;

  /* Retry on a temporary error. Technically an EINTR only happens on a signal,
     and EAGAIN not at all for most of the functions, but expereince is that when
     the system gets really busy, they do occur, lots. So we have to keep trying,
     but still give up and assert after a suitably huge effort. */
  if ((err == EINTR || err == EAGAIN) && ++retry < 1000) {
    PThread::Sleep(10); // Basically just swap out thread to try and clear blockage
    return true;        // Return value to try again
  }

#if PTRACING || P_USE_ASSERTS
  std::ostringstream msg;
  msg << "Function " << funcname << '(' << arg1 << ") failed, errno=" << err << ' ' << strerror(err);
#if P_USE_ASSERTS
  PAssertFunc(location, msg.str().c_str());
#else
  PTrace::Begin(0, location.m_file, location.m_line, NULL, "PTLib") << msg.str() << PTrace::End;
#endif
#endif
  return false;
}


#if defined(P_LINUX)
static int GetSchedParam(PThread::Priority priority, sched_param & param)
{
  /*
    Set realtime scheduling if our effective user id is root (only then is this
    allowed) AND our priority is Highest.
      I don't know if other UNIX OSs have SCHED_FIFO and SCHED_RR as well.

    WARNING: a misbehaving thread (one that never blocks) started with Highest
    priority can hang the entire machine. That is why root permission is 
    neccessary.
  */

  memset(&param, 0, sizeof(sched_param));

  switch (priority) {
    case PThread::HighestPriority :
      param.sched_priority = sched_get_priority_max(SCHED_RR);
      break;

    case PThread::HighPriority :
      param.sched_priority = (sched_get_priority_max(SCHED_RR) + sched_get_priority_min(SCHED_RR))/2;
      break;

#ifdef SCHED_BATCH
    case PThread::LowestPriority :
    case PThread::LowPriority :
      return SCHED_BATCH;
#endif

    default : // PThread::NormalPriority :
      return SCHED_OTHER;
  }

#ifdef RLIMIT_RTPRIO
  struct rlimit rl;
  if (getrlimit(RLIMIT_RTPRIO, &rl) != 0) {
    PTRACE(2, "PTLib", "Could not get Real Time thread priority limit - " << strerror(errno));
    return SCHED_OTHER;
  }

  if ((int)rl.rlim_cur < (int)param.sched_priority) {
    rl.rlim_max = rl.rlim_cur = param.sched_priority;
    if (setrlimit(RLIMIT_RTPRIO, &rl) != 0) {
      PTRACE(geteuid() == 0 || errno != EPERM ? 2 : 3, "PTLib",
             "Could not increase Real Time thread priority limit to " << rl.rlim_cur << " - " << strerror(errno));
      param.sched_priority = 0;
      return SCHED_OTHER;
    }

    PTRACE(4, "PTLib", "Increased Real Time thread priority limit to " << rl.rlim_cur);
  }

  return SCHED_RR;
#else
  if (geteuid() == 0)
    return SCHED_RR;

  param.sched_priority = 0;
  PTRACE(3, "PTLib", "No permission to set priority level " << priority);
  return SCHED_OTHER;
#endif // RLIMIT_RTPRIO
}
#endif


static pthread_mutex_t MutexInitialiser = PTHREAD_MUTEX_INITIALIZER;


#define new PNEW


//////////////////////////////////////////////////////////////////////////////

//
//  Called to construct a PThread for either:
//
//       a) The primordial PProcesss thread
//       b) A non-PTLib thread that needs to use PTLib routines, such as PTRACE
//
//  This is always called in the context of the running thread, so naturally, the thread
//  is not paused
//

PThread::PThread(bool isProcess)
  : m_type(isProcess ? e_IsProcess : e_IsExternal)
  , m_originalStackSize(0)
  , m_threadId(pthread_self())
  , m_uniqueId(GetCurrentUniqueIdentifier())
  , PX_priority(NormalPriority)
#if defined(P_LINUX)
  , PX_startTick(PTimer::Tick())
#endif
  , PX_suspendMutex(MutexInitialiser)
  , PX_suspendCount(0)
  , PX_state(PX_running)
#ifndef P_HAS_SEMAPHORES
  , PX_waitingSemaphore(NULL)
  , PX_WaitSemMutex(MutexInitialiser)
#endif
{
#ifdef P_RTEMS
  PAssertOS(socketpair(AF_INET,SOCK_STREAM,0,unblockPipe) == 0);
#else
  PAssertOS(::pipe(unblockPipe) == 0);
#endif

  if (isProcess)
    return;

  PProcess::Current().InternalThreadStarted(this);
}


//
//  Called to construct a PThread for a normal PTLib thread.
//
//  This is always called in the context of some other thread, and
//  the PThread is always created in the paused state
//
PThread::PThread(PINDEX stackSize,
                 AutoDeleteFlag deletion,
                 Priority priorityLevel,
                 const PString & name)
  : m_type(deletion == AutoDeleteThread ? e_IsAutoDelete : e_IsManualDelete)
  , m_originalStackSize(std::max(stackSize, PThreadMinimumStack))
  , m_threadName(name)
  , m_threadId(PNullThreadIdentifier)  // indicates thread has not started
  , m_uniqueId(0)
  , PX_priority(priorityLevel)
  , PX_suspendMutex(MutexInitialiser)
  , PX_suspendCount(1)
  , PX_state(PX_firstResume) // new thread is actually started the first time Resume() is called.
#ifndef P_HAS_SEMAPHORES
  , PX_waitingSemaphore(NULL)
  , PX_WaitSemMutex(MutexInitialiser)
#endif
{
#ifdef P_RTEMS
  PAssertOS(socketpair(AF_INET,SOCK_STREAM,0,unblockPipe) == 0);
#else
  PAssertOS(::pipe(unblockPipe) == 0);
#endif
  PX_NewHandle("Thread unblock pipe", PMAX(unblockPipe[0], unblockPipe[1]));

  // If need to be deleted automatically, make sure thread that does it runs.
  if (m_type == e_IsAutoDelete)
    PProcess::Current().SignalTimerChange();

  PTRACE(5, "PTLib\tCreated thread " << this << ' ' << m_threadName << " stack=" << m_originalStackSize);
}

//
//  Called to destruct a PThread
//
//  If not called in the context of the thread being destroyed, we need to wait
//  for that thread to stop before continuing
//

void PThread::InternalDestroy()
{
  /* If manual delete, wait for thread to really end before
     proceeding with destruction */
  if (PX_synchroniseThreadFinish.get() != NULL)
    PX_synchroniseThreadFinish->Wait();

  // close I/O unblock pipes
  ::close(unblockPipe[0]);
  ::close(unblockPipe[1]);

#ifndef P_HAS_SEMAPHORES
  pthread_mutex_destroy(&PX_WaitSemMutex);
#endif

  // If the mutex was not locked, the unlock will fail */
  pthread_mutex_trylock(&PX_suspendMutex);
  pthread_mutex_unlock(&PX_suspendMutex);
  pthread_mutex_destroy(&PX_suspendMutex);
}


void PThread::InternalPreMain()
{ 
  // Added this to guarantee that the thread creation (PThread::Restart)
  // has completed before we start the thread. Then the m_threadId has
  // been set.
  pthread_mutex_lock(&PX_suspendMutex);

  PAssert(PX_state == PX_starting, PLogicError);
  PX_state = PX_running;

  m_uniqueId = GetCurrentUniqueIdentifier();
#if defined(P_LINUX)
  PX_startTick = PTimer::Tick();
#endif

  SetThreadName(GetThreadName());

  pthread_mutex_unlock(&PX_suspendMutex);

  PX_Suspended();

  if (PX_priority != NormalPriority)
    SetPriority((Priority)PX_priority.load());

  /* If manual delete thread, there is a race on the thread actually ending
     and the PThread object being deleted. This flag is used to synchronise
     those actions. */
  if (!IsAutoDelete())
    PX_synchroniseThreadFinish.reset(new PSyncPoint());
}


void PThread::InternalPostMain()
{
  /* Bizarely, this can get called by pthread_cleanup_push() when a thread
     is started! Seems to be a load and/or race on use of thread ID's inside
     the system library. Anyway, need to make sure we are really ending. */
  if (PX_state.exchange(PX_finishing) != PX_running)
    return;

#if defined(P_LINUX)
  PX_endTick = PTimer::Tick();
#endif

  /* Need to check this before the InternalThreadEnded() as an auto
     delete thread would be deleted in that function. */
  bool doThreadFinishedSignal = PX_synchroniseThreadFinish.get() != NULL;

  /* The thread changed from manual to auto delete somewhere, so we need to
     do the signal now, due to the thread being deleted in InternalThreadEnded() */
  if (doThreadFinishedSignal && IsAutoDelete()) {
    doThreadFinishedSignal = false; // Don't do it after
    PX_synchroniseThreadFinish->Signal();
  }

  /* If auto delete, "this" may have be deleted any nanosecond after
     this function, as it is asynchronously done by the housekeeping thread. */
  PProcess::Current().InternalThreadEnded(this);

  /* We know the thread is not auto delete and the destructor is either
     not run yet, or is waiting on this signal, so "this" is still safe
     to use. */
  if (doThreadFinishedSignal)
    PX_synchroniseThreadFinish->Signal();
}


void * PThread::PX_ThreadMain(void * arg)
{
#if P_USE_THREAD_CANCEL
  // make sure the cleanup routine is called when the threade cancelled
  pthread_cleanup_push(&PThread::PX_ThreadEnd, arg);
  // Allow cancel to happen any time
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
#endif

  reinterpret_cast<PThread *>(PAssertNULL(arg))->InternalThreadMain();

#if P_USE_THREAD_CANCEL
  pthread_cleanup_pop(0);
#endif

  return NULL;
}


void PThread::PX_ThreadEnd(void * arg)
{
  reinterpret_cast<PThread *>(PAssertNULL(arg))->InternalPostMain();
}


void PThread::Restart()
{
  if (!IsTerminated())
    return;

  PTRACE(2, "PTlib\tRestarting thread " << this << " \"" << GetThreadName() << '"');
  pthread_mutex_lock(&PX_suspendMutex);
  PX_StartThread();
  pthread_mutex_unlock(&PX_suspendMutex);
}


void PThread::PX_StartThread()
{
  // This should be executed inside the PX_suspendMutex to avoid races
  // with the thread starting.
  PX_state = PX_starting;

  pthread_attr_t threadAttr;
  pthread_attr_init(&threadAttr);
  PAssertWithRetry(pthread_attr_setdetachstate, &threadAttr, PTHREAD_CREATE_DETACHED);

  PAssertWithRetry(pthread_attr_setstacksize, &threadAttr, m_originalStackSize);

#if defined(P_LINUX)
  struct sched_param sched_params;
  PAssertWithRetry(pthread_attr_setschedpolicy, &threadAttr, GetSchedParam((Priority)PX_priority.load(), sched_params));
  PAssertWithRetry(pthread_attr_setschedparam,  &threadAttr, &sched_params);
#elif defined(P_RTEMS)
  pthread_attr_setinheritsched(&threadAttr, PTHREAD_EXPLICIT_SCHED);
  pthread_attr_setschedpolicy(&threadAttr, SCHED_OTHER);
  struct sched_param sched_param;
  sched_param.sched_priority = 125; /* set medium priority */
  pthread_attr_setschedparam(&threadAttr, &sched_param);
#endif

  PProcess & process = PProcess::Current();

  size_t checkSize = 0;
  PAssertWithRetry(pthread_attr_getstacksize, &threadAttr, &checkSize);
  PAssert(checkSize == (size_t)m_originalStackSize, "Stack size not set correctly");

  // create the thread
  PAssertWithRetry(pthread_create, &m_threadId, &threadAttr, &PThread::PX_ThreadMain, this);

  // put the thread into the thread list
  process.InternalThreadStarted(this);

  pthread_attr_destroy(&threadAttr);
}


bool PThread::PX_kill(PThreadIdentifier tid, PUniqueThreadIdentifier uid, int sig)
{
  if (!PProcess::IsInitialised())
    return false;

  PProcess & process = PProcess::Current();
  {
    PWaitAndSignal mutex(process.m_threadMutex);
    PProcess::ThreadMap::iterator it = process.m_activeThreads.find(tid);
    if (it == process.m_activeThreads.end() || (uid != 0 && it->second->GetUniqueIdentifier() != uid))
      return false;
  }

  int error = pthread_kill(tid, sig);
  switch (error) {
    case 0:
      return true;

      // If just test for existance, is true even if we don't have permission
    case EPERM:
    case ENOTSUP: // Mac OS-X does this for GCD threads
      return sig == 0; 

#if PTRACING
    case ESRCH:   // Thread not running any more
    case EINVAL:  // Id has never been used for a thread
      break;

    default:
      // Output direct to stream, do not use PTRACE as it might cause an infinite recursion.
      ostream * trace = PTrace::GetStream();
      if (trace != NULL)
          *trace << "pthread_kill failed for thread " << GetIdentifiersAsString(tid, uid)
                 << " errno " << error << ' ' << strerror(error) << endl;
#endif // PTRACING
  }

  return false;
}


void PThread::PX_Suspended()
{
  while (PX_suspendCount > 0) {
    BYTE ch;
    if (::read(unblockPipe[0], &ch, 1) == 1 || errno != EINTR)
    return;

#if P_USE_THREAD_CANCEL
    pthread_testcancel();
#endif
  }
}


void PX_SuspendSignalHandler(int)
{
  PThread * thread = PThread::Current();
  if (thread != NULL)
    thread->PX_Suspended();
}


void PThread::Suspend(PBoolean susp)
{
  PAssertWithRetry(pthread_mutex_lock, &PX_suspendMutex);

  // Check for start up condition, first time Resume() is called
  if (PX_state == PX_firstResume) {
    if (susp)
      PX_suspendCount++;
    else {
      if (PX_suspendCount > 0)
        PX_suspendCount--;
      if (PX_suspendCount == 0)
        PX_StartThread();
    }

    PAssertWithRetry(pthread_mutex_unlock, &PX_suspendMutex);
    return;
  }

  if (!IsTerminated()) {

    // if suspending, then see if already suspended
    if (susp) {
      PX_suspendCount++;
      if (PX_suspendCount == 1) {
        if (m_threadId != pthread_self()) {
          signal(SUSPEND_SIG, PX_SuspendSignalHandler);
          pthread_kill(m_threadId, SUSPEND_SIG);
        }
        else {
          PAssertWithRetry(pthread_mutex_unlock, &PX_suspendMutex);
          PX_SuspendSignalHandler(SUSPEND_SIG);
          return;  // Mutex already unlocked
        }
      }
    }

    // if resuming, then see if to really resume
    else if (PX_suspendCount > 0) {
      PX_suspendCount--;
      if (PX_suspendCount == 0) 
        PXAbortBlock();
    }
  }

  PAssertWithRetry(pthread_mutex_unlock, &PX_suspendMutex);
}


void PThread::Resume()
{
  Suspend(false);
}


PBoolean PThread::IsSuspended() const
{
  PAssertWithRetry(pthread_mutex_lock, &PX_suspendMutex);
  bool suspended = PX_state == PX_starting || (PX_suspendCount != 0 && !IsTerminated());
  PAssertWithRetry(pthread_mutex_unlock, &PX_suspendMutex);
  return suspended;
}


#ifdef P_MACOSX
// obtain thread priority of the main thread
static unsigned long
GetThreadBasePriority ()
{
    thread_basic_info_data_t threadInfo;
    policy_info_data_t       thePolicyInfo;
    unsigned int             count;
    pthread_t baseThread = PProcess::Current().GetThreadId();

    // get basic info
    count = THREAD_BASIC_INFO_COUNT;
    thread_info (pthread_mach_thread_np (baseThread), THREAD_BASIC_INFO,
                 (integer_t*)&threadInfo, &count);

    switch (threadInfo.policy) {
    case POLICY_TIMESHARE:
      count = POLICY_TIMESHARE_INFO_COUNT;
      thread_info(pthread_mach_thread_np (baseThread),
                  THREAD_SCHED_TIMESHARE_INFO,
                  (integer_t*)&(thePolicyInfo.ts), &count);
      return thePolicyInfo.ts.base_priority;

    case POLICY_FIFO:
      count = POLICY_FIFO_INFO_COUNT;
      thread_info(pthread_mach_thread_np (baseThread),
                  THREAD_SCHED_FIFO_INFO,
                  (integer_t*)&(thePolicyInfo.fifo), &count);
      if (thePolicyInfo.fifo.depressed) 
        return thePolicyInfo.fifo.depress_priority;
      return thePolicyInfo.fifo.base_priority;

    case POLICY_RR:
      count = POLICY_RR_INFO_COUNT;
      thread_info(pthread_mach_thread_np (baseThread),
                  THREAD_SCHED_RR_INFO,
                  (integer_t*)&(thePolicyInfo.rr), &count);
      if (thePolicyInfo.rr.depressed) 
        return thePolicyInfo.rr.depress_priority;
      return thePolicyInfo.rr.base_priority;
    }

    return 0;
}
#endif

void PThread::SetPriority(Priority priorityLevel)
{
  PTRACE(4, "PTLib", "Setting thread priority to " << priorityLevel);
  PX_priority.store(priorityLevel);

  if (IsTerminated())
    return;

#if defined(P_LINUX)
  struct sched_param params;
  PAssertWithRetry(pthread_setschedparam, m_threadId, GetSchedParam(priorityLevel, params), &params);

#elif defined(P_ANDROID)
  if (Current() != this) {
    PTRACE(2, "JNI", "Can only set priority for current thread.");
    return;
  }

  if (AndroidJavaVM == NULL) {
    PTRACE(2, "JNI", "JavaVM not set.");
    return;
  }

  JNIEnv *jni = NULL;
  bool detach = false;

  jint err = AndroidJavaVM->GetEnv((void **)&jni, JNI_VERSION_1_6);
  switch (err) {
    case JNI_EDETACHED :
      if ((err = AndroidJavaVM->AttachCurrentThread(&jni, NULL)) != JNI_OK) {
        PTRACE(2, "JNI", "Could not attach JNI environment, error=" << err);
        return;
      }
      detach = true;

    case JNI_OK :
      break;

    default :
      PTRACE(2, "JNI", "Could not get JNI environment, error=" << err);
      return;
  }

  //Get pointer to the java class
  jclass androidOsProcess = (jclass)jni->NewGlobalRef(jni->FindClass("android/os/Process"));
  if (androidOsProcess != NULL) {
    jmethodID setThreadPriority = jni->GetStaticMethodID(androidOsProcess, "setThreadPriority", "(I)V");
    if (setThreadPriority != NULL) {
      static const int Priorities[NumPriorities] = { 19, 10, 0,  -10, -19 };
      jni->CallStaticIntMethod(androidOsProcess, setThreadPriority, Priorities[priorityLevel]);
      PTRACE(5, "JNI", "setThreadPriority " << Priorities[priorityLevel]);
    }
    else {
      PTRACE(2, "JNI", "Could not find setThreadPriority");
    }
  }
  else {
    PTRACE(2, "JNI", "Could not find android.os.Process");
  }

  if (detach)
    AndroidJavaVM->DetachCurrentThread();

#elif defined(P_MACOSX)
  if (priorityLevel == HighestPriority) {
    /* get fixed priority */
    {
      int result;

      thread_extended_policy_data_t   theFixedPolicy;
      thread_precedence_policy_data_t thePrecedencePolicy;
      long                            relativePriority;

      theFixedPolicy.timeshare = false; // set to true for a non-fixed thread
      result = thread_policy_set (pthread_mach_thread_np(m_threadId),
                                  THREAD_EXTENDED_POLICY,
                                  (thread_policy_t)&theFixedPolicy,
                                  THREAD_EXTENDED_POLICY_COUNT);
      if (result != KERN_SUCCESS) {
        PTRACE(1, "thread_policy - Couldn't set thread as fixed priority.");
      }

      // set priority

      // precedency policy's "importance" value is relative to
      // spawning thread's priority
      
      relativePriority = 62 - GetThreadBasePriority();
      PTRACE(3,  "relativePriority is " << relativePriority << " base priority is " << GetThreadBasePriority());
      
      thePrecedencePolicy.importance = relativePriority;
      result = thread_policy_set (pthread_mach_thread_np(m_threadId),
                                  THREAD_PRECEDENCE_POLICY,
                                  (thread_policy_t)&thePrecedencePolicy, 
                                  THREAD_PRECEDENCE_POLICY_COUNT);
      if (result != KERN_SUCCESS) {
        PTRACE(1, "thread_policy - Couldn't set thread priority.");
      }
    }
  }
#endif
}


PThread::Priority PThread::GetPriority() const
{
#if defined(LINUX)
  int policy;
  struct sched_param params;
  
  PAssertWithRetry(pthread_getschedparam, m_threadId, &policy, &params);
  
  switch (policy)
  {
    case SCHED_OTHER:
      break;

    case SCHED_FIFO:
    case SCHED_RR:
      return params.sched_priority > sched_get_priority_min(policy) ? HighestPriority : HighPriority;

#ifdef SCHED_BATCH
    case SCHED_BATCH :
      return LowPriority;
#endif

    default:
      /* Unknown scheduler. We don't know what priority this thread has. */
      PTRACE(1, "PTLib\tPThread::GetPriority: unknown scheduling policy #" << policy);
  }
#endif

  return NormalPriority; /* as good a guess as any */
}


#ifndef P_HAS_SEMAPHORES
void PThread::PXSetWaitingSemaphore(PSemaphore * sem)
{
  PAssertWithRetry(pthread_mutex_lock, &PX_WaitSemMutex);
  PX_waitingSemaphore = sem;
  PAssertWithRetry(pthread_mutex_unlock, &PX_WaitSemMutex);
}
#endif


// Normal Posix threads version
void PThread::Sleep(const PTimeInterval & timeout)
{
  struct timespec ts;
  ts.tv_sec = timeout.GetSeconds();
  ts.tv_nsec = timeout.GetNanoSeconds()%1000000000;

  PPROFILE_PRE_SYSTEM();

  while (nanosleep(&ts, &ts) < 0 && PAssert(errno == EINTR || errno == EAGAIN, POperatingSystemError)) {
#if P_USE_THREAD_CANCEL
    pthread_testcancel();
#endif
  }

  PPROFILE_POST_SYSTEM();
}


void PThread::Yield()
{
  PPROFILE_SYSTEM(
    sched_yield();
  );
}


//
//  Terminate the specified thread
//
void PThread::Terminate()
{
  // if thread was not created by PTLib, then don't terminate it
  if (m_originalStackSize <= 0)
    return;

  // if the thread is already terminated, then nothing to do
  if (IsTerminated())
    return;

  // if thread calls Terminate on itself, then do it
  // don't use PThread::Current, as the thread may already not be in the
  // active threads list
  if (m_threadId == pthread_self()) {
    pthread_exit(0);
    return;   // keeps compiler happy
  }

  // otherwise force thread to die
  PTRACE(2, "PTLib\tForcing termination of thread id=0x" << hex << m_threadId << dec);

  PXAbortBlock();
  if (WaitForTermination(100))
    return;

#ifndef P_HAS_SEMAPHORES
  PAssertWithRetry(pthread_mutex_lock, &PX_WaitSemMutex);
  if (PX_waitingSemaphore != NULL) {
    PAssertWithRetry(pthread_mutex_lock, &PX_waitingSemaphore->mutex);
    PX_waitingSemaphore->queuedLocks--;
    PAssertWithRetry(pthread_mutex_unlock, &PX_waitingSemaphore->mutex);
    PX_waitingSemaphore = NULL;
  }
  PAssertWithRetry(pthread_mutex_unlock, &PX_WaitSemMutex);
#endif

  if (m_threadId != PNullThreadIdentifier) {
#if P_USE_THREAD_CANCEL
    pthread_cancel(m_threadId);
#else
    pthread_kill(m_threadId, SIGKILL);
#endif
    WaitForTermination(100);
  }
}


PBoolean PThread::IsTerminated() const
{
  if (m_type == e_IsProcess)
    return false; // Process is always still running

  switch (PX_state.load()) {
    case PX_starting :
    case PX_firstResume :
      return false;
    case PX_finished:
      return true;
    default :
      break;
  }

  // See if thread is still running, copy variable in case changes between two statements
  pthread_t id = m_threadId;
  if (id == PNullThreadIdentifier)
    return true;

  /* If thread is external, than PTLib doesn't track it state and
     needs to use additional methods to check it is terminated. */
  if (m_type != e_IsExternal)
    return false;

#if P_NO_PTHREAD_KILL
  /* Some flavours of Linux crash in pthread_kill() if the thread id
     is invalid. Now, IMHO, a pthread function that is not itself
     thread safe is utter madness, but apparently, the authors would
     rather change the Posix standard than fix the problem!  What is
     the point of an ESRCH error return for invalid id if it can
     crash on an invalid id? As I said, complete madness.
     
     So, if we have a /proc, we always use that mechanism to determine
     if the external thread still exists. */
  char fn[100];
  snprintf(fn, sizeof(fn), "/proc/%u/task/%u/stat", getpid(), (unsigned)(intptr_t)GetUniqueIdentifier());
  return access(fn, R_OK) != 0;
#else
  return !PX_kill(id, GetUniqueIdentifier(), 0);
#endif
}


void PThread::WaitForTermination() const
{
  WaitForTermination(PMaxTimeInterval);
}


PBoolean PThread::WaitForTermination(const PTimeInterval & maxWait) const
{
  pthread_t id = m_threadId;
  if (id == PNullThreadIdentifier || this == Current()) {
    PTRACE(2, "WaitForTermination on 0x" << hex << id << dec << " short circuited");
    return true;
  }
  
  PTRACE(6, "WaitForTermination on 0x" << hex << id << dec << " for " << maxWait);

  PTimeInterval start = PTimer::Tick();
  while (!IsTerminated()) {
    if ((PTimer::Tick() - start) > maxWait)
      return false;

    Sleep(10); // sleep for 10ms. This slows down the busy loop removing 100%
               // CPU usage and also yeilds so other threads can run.
  }

  PTRACE(6, "WaitForTermination on 0x" << hex << id << dec << " finished");
  return true;
}



PUniqueThreadIdentifier PThread::GetCurrentUniqueIdentifier()
{
#if defined(P_LINUX)
  return syscall(SYS_gettid);
#elif defined(P_MACOSX)
  PUniqueThreadIdentifier id;
  return pthread_threadid_np(::pthread_self(), &id) == 0 ? id : 0;
#else
  return (PUniqueThreadIdentifier)GetCurrentThreadId();
#endif
}


int PThread::PXBlockOnIO(int handle, int type, const PTimeInterval & timeout)
{
  PTRACE(7, "PTLib\tPThread::PXBlockOnIO(" << handle << ',' << type << ')');

  if ((handle < 0) || (handle >= PProcess::Current().GetMaxHandles())) {
    PTRACE(2, "PTLib\tAttempt to use illegal handle in PThread::PXBlockOnIO, handle=" << handle);
    errno = EBADF;
    return -1;
  }

  int retval;

#if P_HAS_POLL
  struct pollfd pfd[2];
  pfd[0].fd = handle;
  switch (type) {
    case PChannel::PXReadBlock :
    case PChannel::PXAcceptBlock :
      pfd[0].events = POLLIN;
      break;

    case PChannel::PXWriteBlock :
    case PChannel::PXConnectBlock :
      pfd[0].events = POLLOUT;
      break;
  }
  pfd[0].events |= POLLERR;

  pfd[1].fd = unblockPipe[0];
  pfd[1].events = POLLIN;

  do {
    retval = ::poll(pfd, PARRAYSIZE(pfd), timeout.GetInterval());
  } while (retval < 0 && errno == EINTR);

  BYTE dummy;
  if (retval > 0 && pfd[1].revents != 0 && ::read(unblockPipe[0], &dummy, 1) == 1) {
    errno = ECANCELED;
    retval = -1;
    PTRACE(6, "PTLib\tUnblocked I/O fd=" << unblockPipe[0]);
  }

#else // P_HAS_POLL

  P_fd_set read_fds;
  P_fd_set write_fds;
  P_fd_set exception_fds;

  do {
    switch (type) {
      case PChannel::PXReadBlock:
      case PChannel::PXAcceptBlock:
        read_fds = handle;
        write_fds.Zero();
        exception_fds.Zero();
        break;
      case PChannel::PXWriteBlock:
        read_fds.Zero();
        write_fds = handle;
        exception_fds.Zero();
        break;
      case PChannel::PXConnectBlock:
        read_fds.Zero();
        write_fds = handle;
        exception_fds = handle;
        break;
      default:
        PAssertAlways(PLogicError);
        return 0;
    }

    // include the termination pipe into all blocking I/O functions
    read_fds += unblockPipe[0];

    P_timeval tval = timeout;
    PPROFILE_SYSTEM(
      retval = ::select(PMAX(handle, unblockPipe[0])+1,
                        read_fds, write_fds, exception_fds, tval);
    );
  } while (retval < 0 && errno == EINTR);

  BYTE dummy;
  if (retval > 0 && read_fds.IsPresent(unblockPipe[0]) && ::read(unblockPipe[0], &ch, 1) == 1) {
    errno = ECANCELED;
    retval =  -1;
    PTRACE(6, "PTLib\tUnblocked I/O fd=" << unblockPipe[0]);
  }

#endif // P_HAS_POLL

  return retval;
}

void PThread::PXAbortBlock() const
{
  static BYTE ch = 0;
  PAssertOS(::write(unblockPipe[1], &ch, 1) == 1);
  PTRACE(6, "PTLib\tUnblocking I/O fd=" << unblockPipe[0] << " thread=" << GetThreadName());
}


///////////////////////////////////////////////////////////////////////////////

PSemaphore::~PSemaphore()
{
#if defined(P_HAS_SEMAPHORES)
  #if defined(P_HAS_NAMED_SEMAPHORES)
    if (m_namedSemaphore.ptr != NULL) {
      PAssertWithRetry(sem_close, m_namedSemaphore.ptr);
    }
    else
  #endif
      PAssertWithRetry(sem_destroy, &m_semaphore);
#else
  PAssert(queuedLocks == 0, "Semaphore destroyed with queued locks");
  PAssertWithRetry(pthread_mutex_destroy, &mutex);
  PAssertWithRetry(pthread_cond_destroy, &condVar);
#endif
}


void PSemaphore::Reset(unsigned initial, unsigned maximum)
{
  m_maximum = std::min(maximum, (unsigned)INT_MAX);
  m_initial = std::min(initial, m_maximum);

#if defined(P_HAS_SEMAPHORES)
  /* Due to bug in some Linux/Kernel versions, need to clear structure manually, sem_init does not do the job.
     See http://stackoverflow.com/questions/1832395/sem-timedwait-not-supported-properly-on-redhat-enterprise-linux-5-3-onwards
     While the above link was for RHEL, seems to happen on some Fedoras as well. */
  memset(&m_semaphore, 0, sizeof(sem_t));

  #if defined(P_HAS_NAMED_SEMAPHORES)
    if (m_name.IsEmpty() && sem_init(&m_semaphore, 0, m_initial) == 0)
      m_namedSemaphore.ptr = NULL;
    else {
      // Since sem_open and sem_unlink are two operations, there is a small
      // window of opportunity that two simultaneous accesses may return
      // the same semaphore. Therefore, the static mutex is used to
      // prevent this.
      static pthread_mutex_t semCreationMutex = PTHREAD_MUTEX_INITIALIZER;
      PAssertWithRetry(pthread_mutex_lock, &semCreationMutex);

      if (!m_name.IsEmpty())
        m_namedSemaphore.ptr = sem_open(m_name, (O_CREAT | O_EXCL), 700, m_initial);
      else {
        PStringStream generatedName;
        generatedName << "/ptlib/" << getpid() << '/' << this;
        sem_unlink(generatedName);
        m_namedSemaphore.ptr = sem_open(generatedName, (O_CREAT | O_EXCL), 700, m_initial);
      }
  
      PAssertWithRetry(pthread_mutex_unlock, &semCreationMutex);
  
      if (!PAssert(m_namedSemaphore.ptr != SEM_FAILED, "Couldn't create named semaphore"))
        m_namedSemaphore.ptr = NULL;
    }
  #else
    if (m_name.IsEmpty())
      PAssertWithRetry(sem_init, &m_semaphore, 0, m_initial);
  #endif
#else
  if (m_name.IsEmpty()) {
    PAssertWithRetry(pthread_mutex_init, &mutex, NULL);
    PAssertWithRetry(pthread_cond_init, &condVar, NULL);
    currentCount = initial;
  }
  else
    currentCount = INT_MAX;
  queuedLocks = 0;
#endif
}


void PSemaphore::Wait() 
{
#if defined(P_HAS_SEMAPHORES)
  PAssertWithRetry(sem_wait, GetSemPtr());
#else
  if (currentCount == INT_MAX)
    return;

  PAssertWithRetry(pthread_mutex_lock, &mutex);

  queuedLocks++;
  PThread::Current()->PXSetWaitingSemaphore(this);

  while (currentCount == 0) {
    PPROFILE_SYSTEM(
      int err = pthread_cond_wait(&condVar, &mutex);
    );
    PAssert(err == 0 || err == EINTR, psprintf("wait error = %i", err));
  }

  PThread::Current()->PXSetWaitingSemaphore(NULL);
  queuedLocks--;

  currentCount--;

  PAssertWithRetry(pthread_mutex_unlock, &mutex);
#endif
}


PBoolean PSemaphore::Wait(const PTimeInterval & waitTime) 
{
  if (waitTime == PMaxTimeInterval) {
    Wait();
    return true;
  }

  // create absolute finish time 
  PTime finishTime;
  finishTime += waitTime;

#if defined(P_HAS_SEMAPHORES)
  #ifdef P_HAS_SEMAPHORES_XPG6
    // use proper timed spinlocks if supported.
    // http://www.opengroup.org/onlinepubs/007904975/functions/sem_timedwait.html

    struct timespec absTime;
    absTime.tv_sec  = finishTime.GetTimeInSeconds();
    absTime.tv_nsec = finishTime.GetMicrosecond() * 1000;

    PPROFILE_PRE_SYSTEM();
    do {
      if (sem_timedwait(GetSemPtr(), &absTime) == 0) {
        PPROFILE_POST_SYSTEM();
        return true;
      }
    } while (errno == EINTR);
    PPROFILE_POST_SYSTEM();

    PAssert(errno == ETIMEDOUT, strerror(errno));

  #else
    // loop until timeout, or semaphore becomes available
    // don't use a PTimer, as this causes the housekeeping
    // thread to get very busy
    PPROFILE_PRE_SYSTEM();
    do {
      if (sem_trywait(GetSemPtr()) == 0) {
        PPROFILE_POST_SYSTEM();
        return true;
      }

      // tight loop is bad karma
      // for the linux scheduler: http://www.ussg.iu.edu/hypermail/linux/kernel/0312.2/1127.html
      PThread::Sleep(10);
    } while (PTime() < finishTime);
    PPROFILE_POST_SYSTEM();
  #endif

    return false;

#else
  if (currentCount == INT_MAX)
    return false;

  struct timespec absTime;
  absTime.tv_sec  = finishTime.GetTimeInSeconds();
  absTime.tv_nsec = finishTime.GetMicrosecond() * 1000;

  PPROFILE_PRE_SYSTEM();

  PAssertWithRetry(pthread_mutex_lock, &mutex);

  PThread * thread = PThread::Current();
  thread->PXSetWaitingSemaphore(this);
  queuedLocks++;

  PBoolean ok = true;
  while (currentCount == 0) {
    int err = pthread_cond_timedwait(&condVar, &mutex, &absTime);
    if (err == ETIMEDOUT) {
      ok = false;
      break;
    }
    else
      PAssert(err == 0 || err == EINTR, psprintf("timed wait error = %i", err));
  }

  thread->PXSetWaitingSemaphore(NULL);
  queuedLocks--;

  if (ok)
    currentCount--;

  PAssertWithRetry(pthread_mutex_unlock, &mutex);

  PPROFILE_POST_SYSTEM();

  return ok;
#endif
}


void PSemaphore::Signal()
{
#if defined(P_HAS_SEMAPHORES)
  PAssertWithRetry(sem_post, GetSemPtr());
#else
  PAssertWithRetry(pthread_mutex_lock, &mutex);

  if (currentCount < m_maximum)
    currentCount++;

  if (queuedLocks > 0) 
    PAssertWithRetry(pthread_cond_signal, &condVar);

  PAssertWithRetry(pthread_mutex_unlock, &mutex);
#endif
}


///////////////////////////////////////////////////////////////////////////////

void PTimedMutex::InitialiseRecursiveMutex(pthread_mutex_t *mutex)
{
#if P_HAS_RECURSIVE_MUTEX

  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);

#if (P_HAS_RECURSIVE_MUTEX == 2)
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
#else
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
#endif

  pthread_mutex_init(mutex, &attr);

  pthread_mutexattr_destroy(&attr);

#else // P_HAS_RECURSIVE_MUTEX

  pthread_mutex_init(mutex, NULL);

#endif // P_HAS_RECURSIVE_MUTEX
}


void PTimedMutex::PlatformConstruct()
{
  InitialiseRecursiveMutex(&m_mutex);
}


PTimedMutex::~PTimedMutex()
{
  int result;
  if (m_lockerId == pthread_self()) {
    // Unlock first
    while (m_lockCount-- > 0 && pthread_mutex_unlock(&m_mutex) == 0)
      ;
    result = pthread_mutex_destroy(&m_mutex);
  }
  else {
    // Wait a bit for someone else to unlock it
    for (PINDEX i = 0; i < 100; ++i) {
      if ((result = pthread_mutex_destroy(&m_mutex)) != EBUSY)
        break;
      PPROFILE_SYSTEM(
        usleep(100);
      );
    }
  }

#ifdef _DEBUG
  PAssert(result == 0, "Error destroying mutex");
#endif

  PMUTEX_DESTROYED();
}


void PTimedMutex::PrintOn(ostream &strm) const
{
  strm << "timed mutex " << this;
  PMutexExcessiveLockInfo::PrintOn(strm);
}


PBoolean PTimedMutex::PlatformWait(const PTimeInterval & waitTime) 
{
#if !P_HAS_RECURSIVE_MUTEX
  // if we already have the mutex, return immediately
  if (pthread_equal(m_lockerId, pthread_self())) {
    // Note this does not need a lock as it can only be touched by the thread
    // which already has the mutex locked.
    ++m_lockCount;
    return true;
  }
#endif

  int result;

  // if waiting indefinitely, then do so
  if (waitTime == PMaxTimeInterval) {
    PPROFILE_SYSTEM(
      result = pthread_mutex_lock(&m_mutex);
    );
  }
  else {
    // create absolute finish time
    PTime finishTime;
    finishTime += waitTime;

#if P_PTHREADS_XPG6

    struct timespec absTime;
    absTime.tv_sec = finishTime.GetTimeInSeconds();
    absTime.tv_nsec = finishTime.GetMicrosecond() * 1000;

    PPROFILE_SYSTEM(
      result = pthread_mutex_timedlock(&m_mutex, &absTime);
    );

#else // P_PTHREADS_XPG6

    PPROFILE_PRE_SYSTEM();
    while ((result = pthread_mutex_trylock(&m_mutex)) == EBUSY) {
      if (PTime() >= finishTime) {
        PPROFILE_POST_SYSTEM();
        return false;
      }
      usleep(10000);
    }
    PPROFILE_POST_SYSTEM();

#endif // P_PTHREADS_XPG6
  }

  switch (result) {
    case 0 :       // Got the lock
    case EDEADLK : // Just a recursive call
#if !P_HAS_RECURSIVE_MUTEX
      PAssert(lockerId == PNullThreadIdentifier && m_lockCount == 0,
          "PMutex acquired whilst locked by another thread");
#endif
      return true;
    case ETIMEDOUT :
      return false; // No assert
  }

  PAssertAlways(psprintf("Mutex lock failed, result=%i", result));
  return false;
}


void PTimedMutex::PlatformSignal(const PDebugLocation * location)
{
#if P_HAS_RECURSIVE_MUTEX

  InternalSignal(location);

#else

  if (!pthread_equal(m_lockerId, pthread_self())) {
    PAssertAlways("PMutex signal failed - no matching wait or signal by wrong thread");
    return;
  }

  // if lock was recursively acquired, then decrement the counter
  // Note this does not need a separate lock as it can only be touched by the thread
  // which already has the mutex locked.
  if (InternalSignal(location))
    return;

#endif

  unsigned threadOpRetry = 0;
  while (PAssertThreadOp(pthread_mutex_unlock(&m_mutex), threadOpRetry, "pthread_mutex_unlock",
          reinterpret_cast<const void *>(&m_mutex), m_location))
    /* wait */;
}


///////////////////////////////////////////////////////////////////////////////

PSyncPoint::PSyncPoint()
{
  PAssertWithRetry(pthread_mutex_init, &mutex, NULL);
  PAssertWithRetry(pthread_cond_init, &condVar, NULL);
  signalled = false;
}

PSyncPoint::PSyncPoint(const PSyncPoint &)
{
  PAssertWithRetry(pthread_mutex_init, &mutex, NULL);
  PAssertWithRetry(pthread_cond_init, &condVar, NULL);
  signalled = false;
}

PSyncPoint::~PSyncPoint()
{
  PAssertWithRetry(pthread_mutex_destroy, &mutex);
  PAssertWithRetry(pthread_cond_destroy, &condVar);
}

void PSyncPoint::Wait()
{
  PPROFILE_PRE_SYSTEM();
  PAssertWithRetry(pthread_mutex_lock, &mutex);
  while (!signalled)
    pthread_cond_wait(&condVar, &mutex);
  signalled = false;
  PAssertWithRetry(pthread_mutex_unlock, &mutex);
  PPROFILE_POST_SYSTEM();
}


PBoolean PSyncPoint::Wait(const PTimeInterval & waitTime)
{
  PPROFILE_PRE_SYSTEM();

  PAssertWithRetry(pthread_mutex_lock, &mutex);

  PTime finishTime;
  finishTime += waitTime;
  struct timespec absTime;
  absTime.tv_sec  = finishTime.GetTimeInSeconds();
  absTime.tv_nsec = finishTime.GetMicrosecond() * 1000;

  int err = 0;
  while (!signalled) {
    err = pthread_cond_timedwait(&condVar, &mutex, &absTime);
    if (err == 0 || err == ETIMEDOUT)
      break;

    /* PAssertOS reports errno, so set it before */
    errno = err;
    PAssertOS(err == EINTR);
  }

  if (err == 0)
    signalled = false;

  PAssertWithRetry(pthread_mutex_unlock, &mutex);

  PPROFILE_POST_SYSTEM();

  return err == 0;
}


void PSyncPoint::Signal()
{
  PAssertWithRetry(pthread_mutex_lock, &mutex);
  signalled = true;
  PAssertWithRetry(pthread_cond_signal, &condVar);
  PAssertWithRetry(pthread_mutex_unlock, &mutex);
}


