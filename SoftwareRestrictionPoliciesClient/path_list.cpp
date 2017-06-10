#include <string.h>
#include <wchar.h>
#include <sys/stat.h>
#include <ctype.h>
#include "path_list.h"

bool path_list::add(const wchar_t* path, size_t pathlen)
{
  // If the path is neither too short nor too long...
  if ((pathlen > 0) && (pathlen < _MAX_PATH)) {
    // If the path exists...
    struct _stat sbuf;
    if (_wstat(path, &sbuf) == 0) {
      wchar_t lastchar;

      // Directory?
      if (sbuf.st_mode & _S_IFDIR) {
        if (path[pathlen - 1] != L'\\') {
          if (pathlen + 1 == _MAX_PATH) {
            return false;
          }

          lastchar = L'\\';
        } else {
          lastchar = L'\0';
        }
      } else if (sbuf.st_mode & _S_IFREG) {
        lastchar = L'\0';
      } else {
        return false;
      }

      // Convert path to lower case.
      wchar_t tmppath[_MAX_PATH];
      for (size_t i = 0; i < pathlen; i++) {
        tmppath[i] = tolower(path[i]);
      }

      if (lastchar) {
        tmppath[pathlen++] = lastchar;
      }

      tmppath[pathlen] = L'\0';

      // If the path has not been inserted yet...
      size_t pos;
      if (!find(tmppath, pathlen, pos)) {
        size_t off = _M_data.length();

        if (_M_data.add(tmppath, pathlen)) {
          if (_M_used == _M_size) {
            size_t size = (_M_size != 0) ? (_M_size * 2) : 32;

            struct string* strings;
            if ((strings = reinterpret_cast<struct string*>(
                             realloc(_M_strings, size * sizeof(struct string))
                           )) == nullptr) {
              return false;
            }

            _M_strings = strings;
            _M_size = size;
          }

          // If not in the last position...
          if (pos < _M_used) {
            memmove(_M_strings + pos + 1,
                    _M_strings + pos,
                    (_M_used - pos) * sizeof(struct string));
          }

          _M_strings[pos].off = off;
          _M_strings[pos].len = pathlen;

          _M_used++;

          return true;
        }
      } else {
        return true;
      }
    }
  }

  return false;
}

bool path_list::find(const wchar_t* path, size_t pathlen) const
{
  // If the path is neither too short nor too long...
  if ((pathlen > 0) && (pathlen < _MAX_PATH)) {
    // Convert path to lower case.
    wchar_t tmppath[_MAX_PATH];
    for (size_t i = 0; i < pathlen; i++) {
      tmppath[i] = tolower(path[i]);
    }

    tmppath[pathlen] = L'\0';

    do {
      size_t pos;
      if (find(tmppath, pathlen, pos)) {
        return true;
      }

      for (--pathlen;
           (pathlen > 0) && (tmppath[pathlen - 1] != L'\\');
           pathlen--);
    } while (pathlen > 0);
  }

  return false;
}

bool path_list::data::add(const wchar_t* path, size_t pathlen)
{
  if (allocate(pathlen)) {
    wmemcpy(_M_data + _M_used, path, pathlen);
    _M_used += pathlen;

    return true;
  }

  return false;
}

bool path_list::data::allocate(size_t size)
{
  if ((size += _M_used) <= _M_size) {
    return true;
  }

  size_t s;
  if (_M_size > 0) {
    size_t tmp;
    if ((tmp = _M_size * 2) >= _M_size) {
      s = tmp;
    } else {
      // Overflow.
      return false;
    }
  } else {
    s = initial_alloc;
  }

  while (s < size) {
    size_t tmp;
    if ((tmp = s * 2) >= s) {
      s = tmp;
    } else {
      // Overflow.
      return false;
    }
  }

  wchar_t* data;
  if ((data = reinterpret_cast<wchar_t*>(
                realloc(_M_data, s * sizeof(wchar_t))
              )) != nullptr) {
    _M_data = data;
    _M_size = s;

    return true;
  }

  return false;
}

bool path_list::find(const wchar_t* path, size_t pathlen, size_t& pos) const
{
  int i = 0;
  int j = _M_used - 1;

  while (i <= j) {
    int mid = (i + j) / 2;

    const struct string* str = _M_strings + mid;

    size_t l = (pathlen < str->len) ? pathlen : str->len;

    int ret;
    if ((ret = wmemcmp(path, _M_data.buffer() + str->off, l)) < 0) {
      j = mid - 1;
    } else if (ret > 0) {
      i = mid + 1;
    } else {
      if (pathlen < str->len) {
        j = mid - 1;
      } else if (pathlen > str->len) {
        i = mid + 1;
      } else {
        pos = mid;
        return true;
      }
    }
  }

  pos = i;

  return false;
}
