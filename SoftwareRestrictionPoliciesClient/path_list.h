#ifndef PATH_LIST_H
#define PATH_LIST_H

#include <stdlib.h>

class path_list {
  public:
    // Constructor.
    path_list();

    // Destructor.
    ~path_list();

    // Add.
    bool add(const wchar_t* path, size_t pathlen);

    // Find.
    bool find(const wchar_t* path, size_t pathlen) const;

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
        const wchar_t* buffer() const;

        // Length.
        size_t length() const;

        // Add.
        bool add(const wchar_t* path, size_t pathlen);

      private:
        static const size_t initial_alloc = 32;

        wchar_t* _M_data;
        size_t _M_size;
        size_t _M_used;

        // Allocate.
        bool allocate(size_t size);
    } _M_data;

    // Find.
    bool find(const wchar_t* path, size_t pathlen, size_t& pos) const;
};

inline path_list::path_list()
  : _M_strings(nullptr),
    _M_size(0),
    _M_used(0)
{
}

inline path_list::~path_list()
{
  if (_M_strings) {
    free(_M_strings);
  }
}

inline path_list::data::data()
  : _M_data(nullptr),
    _M_size(0),
    _M_used(0)
{
}

inline path_list::data::~data()
{
  if (_M_data) {
    free(_M_data);
  }
}

inline const wchar_t* path_list::data::buffer() const
{
  return _M_data;
}

inline size_t path_list::data::length() const
{
  return _M_used;
}

#endif // PATH_LIST_H
