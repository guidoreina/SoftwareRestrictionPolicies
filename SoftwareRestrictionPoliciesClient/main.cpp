#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <fltuser.h>
#include "software_restriction_policies.h"
#include "communication_port.h"

#define TIMEOUT 250 // Milliseconds.

static void usage(const TCHAR* program);

static
bool run(const software_restriction_policies& software_restriction_policies);

static BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);

static bool running = false;

int _tmain(int argc, const TCHAR** argv)
{
  if (argc < 2) {
    usage(argv[0]);
    return -1;
  }

  enum class command {
    run,
    print_signers,
    print_hash,
    query
  };

  command cmd;
  int lastarg;
  if (_tcsicmp(argv[argc - 1], _T("run")) == 0) {
    cmd = command::run;
    lastarg = argc - 1;
  } else if (_tcsicmp(argv[argc - 2], _T("print-signers")) == 0) {
    cmd = command::print_signers;
    lastarg = argc - 2;
  } else if (_tcsicmp(argv[argc - 2], _T("print-hash")) == 0) {
    cmd = command::print_hash;
    lastarg = argc - 2;
  } else if (_tcsicmp(argv[argc - 2], _T("query")) == 0) {
    cmd = command::query;
    lastarg = argc - 2;
  } else {
    usage(argv[0]);
    return -1;
  }

  const TCHAR* signers = nullptr;
  const TCHAR* hashes = nullptr;
  const TCHAR* paths = nullptr;
  bool all_signers = false;

  int i = 1;
  while (i < lastarg) {
    if (_tcsicmp(argv[i], _T("--signers")) == 0) {
      // Last argument?
      if (i + 1 == lastarg) {
        usage(argv[0]);
        return -1;
      }

      signers = argv[i + 1];
      i += 2;
    } else if (_tcsicmp(argv[i], _T("--hashes")) == 0) {
      // Last argument?
      if (i + 1 == lastarg) {
        usage(argv[0]);
        return -1;
      }

      hashes = argv[i + 1];
      i += 2;
    } else if (_tcsicmp(argv[i], _T("--paths")) == 0) {
      // Last argument?
      if (i + 1 == lastarg) {
        usage(argv[0]);
        return -1;
      }

      paths = argv[i + 1];
      i += 2;
    } else if (_tcsicmp(argv[i], _T("--all-signers")) == 0) {
      all_signers = true;
      i++;
    } else {
      usage(argv[0]);
      return -1;
    }
  }

  // Initialize software restriction policies.
  software_restriction_policies software_restriction_policies(all_signers);
  if (software_restriction_policies.init()) {
    // Load files (if needed).
    if (((cmd != command::run) && (cmd != command::query)) ||
        (software_restriction_policies.load(signers, hashes, paths))) {
      switch (cmd) {
        case command::run:
          if (SetConsoleCtrlHandler(HandlerRoutine, TRUE)) {
            run(software_restriction_policies);
            SetConsoleCtrlHandler(HandlerRoutine, FALSE);
          } else {
            _ftprintf_p(stderr, _T("Error setting control handler.\n"));
          }

          break;
        case command::print_signers:
          if (software_restriction_policies.print_signers(argv[argc - 1])) {
            return 0;
          }

          _ftprintf_p(stderr, _T("Error printing signers.\n"));
          break;
        case command::print_hash:
          if (software_restriction_policies.print_hash(argv[argc - 1])) {
            return 0;
          }

          _ftprintf_p(stderr, _T("Error printing hash.\n"));
          break;
        case command::query:
          if (software_restriction_policies.allow(argv[argc - 1])) {
            _tprintf(_T("Allowed.\n"));
            return 0;
          }

          _tprintf(_T("Not allowed.\n"));
          break;
      }
    } else {
      _ftprintf_p(stderr, _T("Error loading files.\n"));
    }
  } else {
    _ftprintf_p(stderr, _T("Error initializing controller.\n"));
  }

  return -1;
}

void usage(const TCHAR* program)
{
  _ftprintf_p(stderr,
              _T("Usage: %s [OPTIONS] <command> [<filename>]\n"),
              program);

  _ftprintf_p(stderr, _T("\n"));
  _ftprintf_p(stderr, _T("Commands:\n"));
  _ftprintf_p(stderr, _T("\trun\n"));
  _ftprintf_p(stderr, _T("\tprint-signers\n"));
  _ftprintf_p(stderr, _T("\tprint-hash\n"));
  _ftprintf_p(stderr, _T("\tquery\n"));
  _ftprintf_p(stderr, _T("\n"));
  _ftprintf_p(stderr, _T("\n"));
  _ftprintf_p(stderr, _T("Options:\n"));
  _ftprintf_p(stderr, _T("\t--signers <filename>\n"));
  _ftprintf_p(stderr, _T("\t--hashes <filename>\n"));
  _ftprintf_p(stderr, _T("\t--paths <filename>\n"));
  _ftprintf_p(stderr, _T("\t--all-signers\n"));
  _ftprintf_p(stderr, _T("\n"));
}

bool run(const software_restriction_policies& software_restriction_policies)
{
  static const size_t FILENAME_MAX_LEN = 4 * 1024;

  struct request_message {
    FILTER_MESSAGE_HEADER hdr;
    wchar_t filename[FILENAME_MAX_LEN];
  };

  static const size_t REQUEST_MAX_SIZE = sizeof(FILTER_MESSAGE_HEADER) +
                                         FILENAME_MAX_LEN;

  struct reply_message {
    FILTER_REPLY_HEADER hdr;
    int reply;
  };

  static const size_t RESPONSE_SIZE = sizeof(FILTER_REPLY_HEADER) + sizeof(int);

  // Open connection to driver.
  HANDLE port;
  if (FilterConnectCommunicationPort(COMMUNICATION_PORT,
                                     0,
                                     NULL,
                                     0,
                                     NULL,
                                     &port) == S_OK) {
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(OVERLAPPED));

    // Create event.
    if ((overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL)) != NULL) {
      running = true;

      do {
        request_message request;
        reply_message reply;

        // Receive message.
        overlapped.InternalHigh = 0;

        switch (HRESULT_CODE(FilterGetMessage(port,
                                              &request.hdr,
                                              REQUEST_MAX_SIZE,
                                              &overlapped))) {
          case ERROR_IO_PENDING:
            if (WaitForSingleObject(overlapped.hEvent,
                                    TIMEOUT) != WAIT_OBJECT_0) {
              break;
            }

            // Fall through.
          case S_OK:
            reply.hdr.Status = 0;
            reply.hdr.MessageId = request.hdr.MessageId;

            if (overlapped.InternalHigh < REQUEST_MAX_SIZE) {
              size_t filenamelen = (overlapped.InternalHigh -
                                    sizeof(FILTER_MESSAGE_HEADER)
                                   ) /
                                   sizeof(wchar_t);

              request.filename[filenamelen] = 0;

              const wchar_t* filename = request.filename;

              if ((filenamelen > 4) &&
                  (wmemcmp(request.filename, L"\\??\\", 4) == 0)) {
                filename += 4;
              }

              reply.reply =
                software_restriction_policies.allow(filename) ? 1 : 0;

#if _DEBUG
              _tprintf(_T("Filename: '%ls' => %s.\n"),
                       filename,
                       reply.reply ? _T("allowed") : _T("not allowed"));
#endif // _DEBUG
            } else {
              reply.reply = 0;
            }

            FilterReplyMessage(port,
                               reinterpret_cast<FILTER_REPLY_HEADER*>(&reply),
                               RESPONSE_SIZE);

            break;
        }
      } while (running);

      CloseHandle(overlapped.hEvent);
      CloseHandle(port);

#if _DEBUG
      _tprintf(_T("Exiting...\n"));
#endif

      return true;
    }

    CloseHandle(port);
  }

  return false;
}

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
  running = false;
  return TRUE;
}
