/*
 * pprocess.h
 *
 * Operating System Process (running program executable) class.
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

#ifndef PTLIB_PROCESS_H
#define PTLIB_PROCESS_H

#ifdef P_USE_PRAGMA
#pragma interface
#endif

#include <ptlib/mutex.h>
#include <ptlib/syncpoint.h>
#include <ptlib/thread.h>
#include <ptlib/pfactory.h>


/**Create a process.
   This macro is used to create the components necessary for a user PWLib
   process. For a PWLib program to work correctly on all platforms the
   main() function must be defined in the same module as the
   instance of the application.
 */
#ifdef P_VXWORKS
#define PCREATE_PROCESS(cls) \
  cls instance; \
  instance.InternalMain();
#elif defined(P_RTEMS)
#define PCREATE_PROCESS(cls) \
extern "C" {\
   void* POSIX_Init( void* argument) \
     { \
       static cls instance; \
       exit( instance.InternalMain() ); \
     } \
}
#else
#define PCREATE_PROCESS(cls) \
  int main(int argc, char * argv[]) \
    { \
      cls *pInstance = new cls(); \
      pInstance->PreInitialise(argc, argv); \
      int terminationValue = pInstance->InternalMain(); \
      delete pInstance; \
      return terminationValue; \
    }
#endif // P_VXWORKS

/*$MACRO PDECLARE_PROCESS(cls,ancestor,manuf,name,major,minor,status,build)
   This macro is used to declare the components necessary for a user PWLib
   process. This will declare the PProcess descendent class, eg PApplication,
   and create an instance of the class. See the <code>PCREATE_PROCESS</code> macro
   for more details.
 */
#define PDECLARE_PROCESS(cls,ancestor,manuf,name,major,minor,status,build) \
  class cls : public ancestor { \
    PCLASSINFO(cls, ancestor); \
    public: \
      cls() : ancestor(manuf, name, major, minor, status, build) { } \
    private: \
      virtual void Main(); \
  };

class PExternalThread;

///////////////////////////////////////////////////////////////////////////////
// PProcess

/**This class represents an operating system process. This is a running
   "programme" in the  context of the operating system. Note that there can
   only be one instance of a PProcess class in a given programme.
   
   The instance of a PProcess or its GUI descendent <code>PApplication</code> is
   usually a static variable created by the application writer. This is the
   initial "anchor" point for all data structures in an application. As the
   application writer never needs to access the standard system
   <code>main()</code> function, it is in the library, the programmes
   execution begins with the virtual function <code>PThread::Main()</code> on a
   process.
 */
class PProcess : public PThread
{
  PCLASSINFO(PProcess, PThread);

  public:
  /**@name Construction */
  //@{
    /// Release status for the program.
    enum CodeStatus {
      AlphaCode,        ///< Code is still very much under construction.
      BetaCode,         ///< Code is largely complete and is under test.
      ReleaseCode,      ///< Code has all known bugs removed and is shipping.
      HotfixCode        ///< Code has been updated after shipping
    };

    /** Create a new process instance.
     */
    PProcess(
      const char * manuf = "",         ///< Name of manufacturer
      const char * name = "",          ///< Name of product
      unsigned majorVersion = 1,       ///< Major version number of the product
      unsigned minorVersion = 0,       ///< Minor version number of the product
      CodeStatus status = ReleaseCode, ///< Development status of the product
      unsigned patchVersion = 1,       ///< Patch version number of the product
      bool library = false,            ///< PProcess is a library rather than an application
      bool suppressStartup = false,    ///< Do not execute Startup()
      unsigned oemVersion = 0          ///< OEM version number of the product
    );
  //@}

  /**@name Overrides from class PObject */
  //@{
    /**Compare two process instances. This should almost never be called as
       a programme only has access to a single process, its own.

       @return
       <code>EqualTo</code> if the two process object have the same name.
     */
    Comparison Compare(
      const PObject & obj   ///< Other process to compare against.
    ) const;

    /**This will print out performance indicators for the process.
       Includes CPU, Memory, Threads & High water marks for various resources.
      */
    virtual void PrintOn(
      ostream & strm
    ) const;
  //@}

  /**@name Overrides from class PThread */
  //@{
    /**Terminate the process. Usually only used in abnormal abort situation.
     */
    virtual void Terminate();
  //@}

  /**@name Process information functions */
  //@{
    /**Get the current processes object instance. The <i>current process</i>
       is the one the application is running in.
       
       @return
       pointer to current process instance.
     */
    static PProcess & Current();

    /**Start up all items registered with PProcessStartupFactory.
      */
    void Startup();

    /** Return the operating system thread identifiers of all threads.
        Note, this only returns the threads that PTLib knows about. Typically
        as it was created using a PThread. Also the thread could disappear at
        any moment and the individual identifier no longer be valid.
        @rturn true if there are identifiers available.
      */
    bool GetAllThreadIdentifiers(
      std::vector<PThreadIdentifier> & identifiers   ///< Returned identifiers
    );

    /** Return the thread for the operating system thread identifier.
        Note, the return value is very dangerous to use as, under some
        circumstances, it may be deleted at any moment. For example, if the
        thread is an AutoDeleteThread mode.
      */
    PThread * GetThread(
      PThreadIdentifier threadId    ///< Identifier if thread to get
    ) const;

    /**Callback for when a thread is started by the PTLib system. Note this is
       called in the context of the new thread.
      */
    virtual void OnThreadStart(
      PThread & thread
    );

    /**Callback for when a thread is ended if wqas started in the PTLib system.
       Note this is called in the context of the old thread.
      */
    virtual void OnThreadEnded(
      PThread & thread
    );

    /**Callback for when a ^C (SIGINT), hangup (SIGHUP) or termination request
       (SIGTERM) is received by process.

       Note this function is called asynchronously and there may be many
       limitations on what can and cannot be done depending on the underlying
       operating system. It is recommeneded that this does no more than set
       flags and return.

       Default behaviour returns false and the process is killed.

       @return true if the process is to be allowed to continue, false otherwise.
      */
    virtual bool OnInterrupt(
      bool terminating ///< true if process terminating.
    );

    /**Determine if the current processes object instance has been initialised.
       If this returns true it is safe to use the PProcess::Current() function.
       
       @return
       true if process class has been initialised.
     */
    static PBoolean IsInitialised();

    /**Set the termination value for the process.
    
       The termination value is an operating system dependent integer which
       indicates the processes termiantion value. It can be considered a
       "return value" for an entire programme.
     */
    void SetTerminationValue(
      int value  ///< Value to return a process termination status.
    );

    /**Get the termination value for the process.
    
       The termination value is an operating system dependent integer which
       indicates the processes termiantion value. It can be considered a
       "return value" for an entire programme.
       
       @return
       integer termination value.
     */
    int GetTerminationValue() const;

    /**Get the programme arguments. Programme arguments are a set of strings
       provided to the programme in a platform dependent manner.
    
       @return
       argument handling class instance.
     */
    PArgList & GetArguments();

    /**Get the name of the manufacturer of the software. This is used in the
       default "About" dialog box and for determining the location of the
       configuration information as used by the <code>PConfig</code> class.

       The default for this information is the empty string.
    
       @return
       string for the manufacturer name eg "Equivalence".
     */
    virtual const PString & GetManufacturer() const;

    /**Get the name of the process. This is used in the
       default "About" dialog box and for determining the location of the
       configuration information as used by the <code>PConfig</code> class.

       The default is the title part of the executable image file.

       @return
       string for the process name eg "MyApp".
     */
    virtual const PString & GetName() const;

    /**Get the version of the software. This is used in the default "About"
       dialog box and for determining the location of the configuration
       information as used by the <code>PConfig</code> class.

       If the <code>full</code> parameter is true then a version string
       built from the major, minor, status and build veriosn codes is
       returned. If false then only the major and minor versions are
       returned.

       The default for this information is "1.0".
    
       @return
       string for the version eg "1.0b3".
     */
    virtual PString GetVersion(
      PBoolean full = true ///< true for full version, false for short version.
    ) const;

    /**Get the processes executable image file path.

       @return
       file path for program.
     */
    const PFilePath & GetFile() const;

    /**Get the platform dependent process identifier for the process.
       This is an arbitrary (and unique) integer attached to a process by the
       operating system.

       @return
       Process ID for process.
     */
    PProcessIdentifier GetProcessID() const { return m_processID; }

    /**Get the platform dependent process identifier for the currentprocess.
       This is an arbitrary (and unique) integer attached to a process by the
       operating system.

       @return
       Process ID for current process.
     */
    static PProcessIdentifier GetCurrentProcessID();

    /**Indicate if this is the second, or more, instance of this executable.
      */
    bool IsMultipleInstance() const;

    /**Return the time at which the program was started 
    */
    PTime GetStartTime() const;

    struct MemoryUsage {
      MemoryUsage()
        : m_virtual(0)
        , m_resident(0)
        , m_max(0)
        , m_current(0)
        , m_blocks(0)
        { }

      size_t m_virtual;
      size_t m_resident;
      size_t m_max;
      size_t m_current;
      size_t m_blocks;
    };

    /**Get process memory suage.
      */
    void GetMemoryUsage(
      MemoryUsage & usage
    ) const;

    PPROFILE_EXCLUDE(
    /** Get the process execution times.
     */
    bool GetProcessTimes(
      Times & times   ///< Times for thread execution.
    ) const
    );

    PPROFILE_EXCLUDE(
    /** Get the system execution times.
     */
    static bool GetSystemTimes(
      Times & times   ///< Times for thread execution.
    ));

    /**Get the effective user name of the owner of the process, eg "root" etc.
       This is a platform dependent string only provided by platforms that are
       multi-user. Note that some value may be returned as a "simulated" user.
       For example, in MS-DOS an environment variable

       @return
       user name of processes owner.
     */
    PString GetUserName() const;

    /**Set the effective owner of the process.
       This is a platform dependent string only provided by platforms that are
       multi-user.

       For unix systems if the username may consist exclusively of digits and
       there is no actual username consisting of that string then the numeric
       uid value is used. For example "0" is the superuser. For the rare
       occassions where the users name is the same as their uid, if the
       username field starts with a '#' then the numeric form is forced.

       If an empty string is provided then original user that executed the
       process in the first place (the real user) is set as the effective user.

       The permanent flag indicates that the user will not be able to simple
       change back to the original user as indicated above, ie for unix
       systems setuid() is used instead of seteuid(). This is not necessarily
       meaningful for all platforms.

       @return
       true if processes owner changed. The most common reason for failure is
       that the process does not have the privilege to change the effective user.
      */
    PBoolean SetUserName(
      const PString & username, ///< New user name or uid
      PBoolean permanent = false    ///< Flag for if effective or real user
    );

    /**Get the "home" directory for the logged in user.
       This checke dthe environment variable HOME first, and if not set tries
       to determine the home directory in a platform dependent manner.
      */
    PDirectory GetHomeDirectory() const;

    /**Get the effective group name of the owner of the process, eg "root" etc.
       This is a platform dependent string only provided by platforms that are
       multi-user. Note that some value may be returned as a "simulated" user.
       For example, in MS-DOS an environment variable

       @return
       group name of processes owner.
     */
    PString GetGroupName() const;

    /**Set the effective group of the process.
       This is a platform dependent string only provided by platforms that are
       multi-user.

       For unix systems if the groupname may consist exclusively of digits and
       there is no actual groupname consisting of that string then the numeric
       uid value is used. For example "0" is the superuser. For the rare
       occassions where the groups name is the same as their uid, if the
       groupname field starts with a '#' then the numeric form is forced.

       If an empty string is provided then original group that executed the
       process in the first place (the real group) is set as the effective
       group.

       The permanent flag indicates that the group will not be able to simply
       change back to the original group as indicated above, ie for unix
       systems setgid() is used instead of setegid(). This is not necessarily
       meaningful for all platforms.

       @return
       true if processes group changed. The most common reason for failure is
       that the process does not have the privilege to change the effective
       group.
      */
    PBoolean SetGroupName(
      const PString & groupname, ///< New group name or gid
      PBoolean permanent = false     ///< Flag for if effective or real group
    );

    /**Get the maximum file handle value for the process.
       For some platforms this is meaningless.

       @return
       user name of processes owner.
     */
    int GetMaxHandles() const;

    /**Set the maximum number of file handles for the process.
       For unix systems the user must be run with the approriate privileges
       before this function can set the value above the system limit.

       For some platforms this is meaningless.

       @return
       true if successfully set the maximum file hadles.
      */
    PBoolean SetMaxHandles(
      int newLimit  ///< New limit on file handles
    );

#if P_CONFIG_FILE
    /**Get the default file to use in PConfig instances.
      */
    virtual PString GetConfigurationFile();

    /**Set the default file or set of directories to search for use in PConfig.
       To find the .ini file for use in the default PConfig() instance, this
       explicit filename is used, or if it is a set of directories separated
       by either ':' or ';' characters, depending on platform, then the
       application base name postfixed with ".ini" is searched for through
       those directories.

       The search is actually done when the GetConfigurationFile() is called,
       this function only sets the internal variable.

       Note for Windows, a path beginning with "HKEY_LOCAL_MACHINE\\" or
       "HKEY_CURRENT_USER\\" will actually search teh system registry for the
       application base name only (no ".ini") in that folder of the registry.
      */
    void SetConfigurationPath(
      const PString & path   ///< Explicit file or set of directories
    );
#endif // P_CONFIG_FILE
  //@}

  /**@name Operating System information functions */
  //@{
    /**Get the class of the operating system the process is running on, eg
       "unix".
       
       @return
       String for OS class.
     */
    static PString GetOSClass();

    /**Get the name of the operating system the process is running on, eg
       "Linux".
       
       @return
       String for OS name.
     */
    static PString GetOSName();

    /**Get the hardware the process is running on, eg "sparc".
       
       @return
       String for OS name.
     */
    static PString GetOSHardware();

    /**Get the version of the operating system the process is running on, eg
       "2.0.33".
       
       @return
       String for OS version.
     */
    static PString GetOSVersion();

    /**See if operating system is later than the version specified.

       @return
       true if OS version leter than or equal to parameters.
     */
    static bool IsOSVersion(
      unsigned major,     ///< Major version number
      unsigned minor = 0, ///< Minor version number
      unsigned build = 0  ///< Build number
    );

    /**Get the configuration directory of the operating system the process is
       running on, eg "/etc" for Unix, "c:\windows" for Win95 or
       "c:\winnt\system32\drivers\etc" for NT.

       @return
       Directory for OS configuration files.
     */
    static PDirectory GetOSConfigDir();

    /**Get the version of the PTLib library the process is running on, eg
       "2.5beta3".
       
       @return
       String for library version.
     */
    static PString GetLibVersion();

    /// Version information
    struct VersionInfo
    {
      unsigned     m_major;
      unsigned     m_minor;
      CodeStatus   m_status;
      unsigned     m_patch;
      unsigned     m_oem;
      unsigned     m_svn;
      const char * m_git;

      /// Build standard format string from version information
      PString AsString(bool full = true) const;
    };
  //@}

    /**Internal initialisation function called directly from
       <code>InternalMain()</code>. The user should never call this function.
     */
    void PreInitialise(
      int argc,     // Number of program arguments.
      char ** argv  // Array of strings for program arguments.
    );

    /// Main function for process, called from real main after initialisation
    virtual int InternalMain(void * arg = NULL);

  //@{
    /// Add all the C run-time signal handlers
    virtual void AddRunTimeSignalHandlers(
      const int * signals = NULL
    );

    /// Remove all the C run-time signal handlers
    virtual void RemoveRunTimeSignalHandlers();

    /// Asynchronous C run-time signal handler, direct callback from OS
    virtual void AsynchronousRunTimeSignal(
      int signal, ///< Signal number
      PProcessIdentifier source  ///< Source for signal, typically the PID of the sender
    );

    struct RunTimeSignalInfo {
      int                m_signal;
      PProcessIdentifier m_source;
    };

    /// Synchronous C run-time signal handler, this is executed in the housekeeper thread
    virtual void HandleRunTimeSignal(const RunTimeSignalInfo & signalInfo);
    virtual void HandleRunTimeSignal(int signal); // Backward compatibility

    /// Get the name of the signal
    static const char * GetRunTimeSignalName(int signal);
  //@}

    /**@name Operating System URL manager functions */
    /**
        This class can be used to register various URL types with the host operating system
        so that URLs will automatically launch the correct application.

        The simplest way to use these functions is to add the code similar to the following
        to the Main function of the PProcess descendant

            PString urlTypes("sip\nh323\nsips\nh323s");
            if (!PProcess::HostSystemURLHandlerInfo::RegisterTypes(urlTypes, false))
              PProcess::HostSystemURLHandlerInfo::RegisterTypes(urlTypes, true);

        This will check to see if the URL types sip, h323, sips and h323s are registered
        with the operating system to launch the current application. If they are not, it
        will rewrite the system configuraton so that they will.

        For more information on the Windows implementation, see the following link:

              http://msdn2.microsoft.com/en-us/library/aa767914.aspx
      */
    //@{
    class HostSystemURLHandlerInfo 
    {
      public:
        HostSystemURLHandlerInfo()
        { }

        HostSystemURLHandlerInfo(const PString & t)
          : type(t)
        { }

        static bool RegisterTypes(const PString & types, bool force = true);

        void SetIcon(const PString & icon);
        PString GetIcon() const;

        void SetCommand(const PString & key, const PString & command);
        PString GetCommand(const PString & key) const;

        bool GetFromSystem();
        bool CheckIfRegistered();

        bool Register();

        PString type;

    #if _WIN32
        PString iconFileName;
        PStringToString cmds;
    #endif
    };
  //@}

    virtual bool IsServiceProcess() const;
    bool SignalTimerChange();

  protected:
    void PlatformConstruct();
    void PlatformDestruct();

  // Member variables
    bool m_library;                   // Indication PTLib is being used as a library for an external process.
    int  m_terminationValue;            // Application return value

    PString m_manufacturer;             // Application manufacturer name.
    PString m_productName;              // Application executable base name from argv[0]

    VersionInfo m_version;            // Process (applications) version

    PFilePath    m_executableFile;      // Application executable file from argv[0] (not open)
    PStringArray m_configurationPaths;  // Explicit file or set of directories to find default PConfig
    PArgList     m_arguments;           // The list of arguments
    int          m_maxHandles;          // Maximum number of file handles process can open.

    PTime m_programStartTime;           // time at which process was intantiated, i.e. started

    atomic<bool> m_shuttingDown;

    // Do not write trace logs while holding m_threadMutex, as most trace logs lock
    // the target log mutex before obtaining this in PThread::Current().
    PCriticalSection m_threadMutex; 

    typedef std::map<PThreadIdentifier, PThread *> ThreadMap;
    ThreadMap m_activeThreads;
    void InternalThreadStarted(PThread * thread);
    void InternalThreadEnded(PThread * thread);
    
    typedef std::list< PSharedPtr<PExternalThread> > ThreadList;
    ThreadList m_externalThreads;
    PSyncQueue<PThread*> m_autoDeleteThreads;

    atomic<bool>   m_keepingHouse;
    PThread      * m_houseKeeper; // Thread for doing timers, thread clean up etc.
    PSyncPoint     m_signalHouseKeeper;
    void HouseKeeping();

#if P_TIMERS
    PTimer::List * m_timerList;
    friend PTimer::List * PTimer::TimerList();
#endif

    PProcessIdentifier m_processID;

    static PRunTimeSignalHandler PlatformSetRunTimeSignalHandler(int signal);
    static void PlatformResetRunTimeSignalHandler(int signal, PRunTimeSignalHandler previous);
    static POrdinalToString::Initialiser const InternalSigNames[];

    std::vector<PRunTimeSignalHandler> m_previousRunTimeSignalHandlers;
    std::vector<RunTimeSignalInfo> m_RunTimeSignalsQueueBuffer;
    size_t m_RunTimeSignalsQueueIn, m_RunTimeSignalsQueueOut;
    PCriticalSection m_RunTimeSignalsQueueMutex;
    void InternalPostRunTimeSignal(int signal, PProcessIdentifier source);
    void InternalHandleRunTimeSignal(const RunTimeSignalInfo & signalInfo);

#if PTRACING
    PDECLARE_NOTIFIER(PTimer, PProcess, ProfileUpdateLogTimer) { PTRACE(3, "PTLibProfile", *this); }
    void PrintProfileOn(ostream & strm);
    PTimer         * m_profileProcessTimer;
    PCriticalSection m_profileProcessMutex;
    Times            m_profileLastProcessTimes;
    set<Times>       m_profileLastThreadTimes;
#endif // PTRACING

  friend class PThread;


// Include platform dependent part of class
#ifdef _WIN32
#include "msos/ptlib/pprocess.h"
#else
#include "unix/ptlib/pprocess.h"
#endif
};


/** Class for a process that is a dynamically loaded library.
 */
 class PLibraryProcess : public PProcess
 {
  PCLASSINFO(PLibraryProcess, PProcess);

  public:
  /**@name Construction */
  //@{
    /** Create a new process instance.
     */
    PLibraryProcess(
      const char * manuf = "",             ///< Name of manufacturer
      const char * name = "",              ///< Name of product
      unsigned majorVersionNum = 1,        ///< Major version number of the product
      unsigned minorVersionNum = 0,        ///< Minor version number of the product
      CodeStatus statusCode = ReleaseCode, ///< Development status of the product
      unsigned buildNum = 1,               ///< Build number of the product
      bool suppressStartup = false         ///< Do not execute Startup()
    ) : PProcess(manuf, name, majorVersionNum, minorVersionNum, statusCode, buildNum, true, suppressStartup) { }
  //@}

    ///< Dummy Main() as libraries do not have one.
    virtual void Main() { }
};


/*
 *  one instance of this class (or any descendants) will be instantiated
 *  via PGenericFactory<PProessStartup> one "main" has been started, and then
 *  the OnStartup() function will be called. The OnShutdown function will
 *  be called after main exits, and the instances will be destroyed if they
 *  are not singletons
 */
class PProcessStartup : public PObject
{
  PCLASSINFO(PProcessStartup, PObject)
  public:
    virtual void OnStartup()  { }
    virtual void OnShutdown() { }
};

typedef PFactory<PProcessStartup> PProcessStartupFactory;

#if PTRACING

// using an inline definition rather than a #define crashes gcc 2.95. Go figure
#define P_DEFAULT_TRACE_OPTIONS ( PTrace::Blocks | PTrace::Timestamp | PTrace::Thread | PTrace::FileAndLine )

template <unsigned level, unsigned options = P_DEFAULT_TRACE_OPTIONS >
class PTraceLevelSetStartup : public PProcessStartup
{
  public:
    void OnStartup()
    { PTrace::Initialise(level, NULL, options); }
};

#endif // PTRACING


#endif // PTLIB_PROCESS_H


// End Of File ///////////////////////////////////////////////////////////////
