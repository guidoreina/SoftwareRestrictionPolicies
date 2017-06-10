#ifndef STRING_LIST_H
#define STRING_LIST_H

#include <stdlib.h>
#include <string.h>

template<typename _CharT>
class string_list {
  public:
    typedef typename _CharT char_type;

    // Constructor.
    string_list();

    // Destructor.
    ~string_list();

    // Add.
    bool add(const char_type* s, size_t len);

    // Find.
    bool find(const char_type* s, size_t len) const;

  private:
    struct string {
      size_t off;
      size_t len;
    };

    struct string* _M_strings;
    size_t _M_size;
    size_t _M_used;

    class data {
      public:
        // Constructor.
        data();

        // Destructor.
        ~data();

        // Get buffer.
        const char_type* buffer() const;

        // Length.
        size_t length() const;

        // Add.
        bool add(const char_type* s, size_t len);

      private:
        static const size_t initial_alloc = 32;

        char_type* _M_data;
        size_t _M_size;
        size_t _M_used;

        // Allocate.
        bool allocate(size_t size);
    } _M_data;

    // Find.
    bool find(const char_type* s, size_t len, size_t& pos) const;
};

template<typename _CharT>
inline string_list<_CharT>::string_list()
  : _M_strings(nullptr),
    _M_size(0),
    _M_used(0)
{
}

template<typename _CharT>
inline string_list<_CharT>::~string_list()
{
  if (_M_strings) {
    free(_M_strings);
  }
}

template<typename _CharT>
bool string_list<_CharT>::add(const char_type* s, size_t len)
{
  // If the string has not been inserted yet...
  size_t pos;
  if (!find(s, len, pos)) {
    size_t off = _M_data.length();

    if (_M_data.add(s, len)) {
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
      _M_strings[pos].len = len;

      _M_used++;
    } else {
      return false;
    }
  }

  return true;
}

template<typename _CharT>
inline bool string_list<_CharT>::find(const char_type* s, size_t len) const
{
  size_t pos;
  return find(s, len, pos);
}

template<typename _CharT>
inline string_list<_CharT>::data::data()
  : _M_data(nullptr),
    _M_size(0),
    _M_used(0)
{
}

template<typename _CharT>
inline string_list<_CharT>::data::~data()
{
  if (_M_data) {
    free(_M_data);
  }
}

template<typename _CharT>
inline const typename string_list<_CharT>::char_type*
string_list<_CharT>::data::buffer() const
{
  return _M_data;
}

template<typename _CharT>
inline size_t string_list<_CharT>::data::length() const
{
  return _M_used;
}

template<typename _CharT>
bool string_list<_CharT>::data::add(const char_type* s, size_t len)
{
  if (allocate(len)) {
    memcpy(_M_data + _M_used, s, len * sizeof(char_type));
    _M_used += len;

    return true;
  }

  return false;
}

template<typename _CharT>
bool string_list<_CharT>::data::allocate(size_t size)
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

  char_type* data;
  if ((data = reinterpret_cast<char_type*>(
                realloc(_M_data, s * sizeof(char_type))
              )) != nullptr) {
    _M_data = data;
    _M_size = s;

    return true;
  }

  return false;
}

template<typename _CharT>
bool string_list<_CharT>::find(const char_type* s,
                               size_t len,
                               size_t& pos) const
{
  int i = 0;
  int j = _M_used - 1;

  while (i <= j) {
    int mid = (i + j) / 2;

    const struct string* str = _M_strings + mid;

    size_t l = (len < str->len) ? len : str->len;

    int ret;
    if ((ret = memcmp(s,
                      _M_data.buffer() + str->off,
                      l * sizeof(char_type))) < 0) {
      j = mid - 1;
    } else if (ret > 0) {
      i = mid + 1;
    } else {
      if (len < str->len) {
        j = mid - 1;
      } else if (len > str->len) {
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

#endif // STRING_LIST_H
