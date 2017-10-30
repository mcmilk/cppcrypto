
#include "stdafx.h"
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>

#include "compatibility.h"
#include "file_wrapper.h"

using namespace std;

bool gen_random_bytes(unsigned char* buffer, size_t buflen);

file_wrapper::file_wrapper(const wstring& filename) 
	: file(filename), success(false)
{
	if (!file_exists())
		throw runtime_error("No such file or directory");

	if (is_directory())
		throw runtime_error("Input file is a directory");

	unsigned char buf[64];
	gen_random_bytes(buf, sizeof(buf));
	wostringstream wstr;
	for (size_t i = 0; i < sizeof(buf); i++)
		wstr << setfill(_T('0')) << setw(2) << hex << (unsigned int)buf[i];
	tmpfile = wstr.str();

	ofile.exceptions(ios::badbit | ios::failbit);
	ifile.exceptions(ios::badbit | ios::failbit);

	ifile.open(file.c_str(), ios::in | ios::binary);
	ofile.open(tmpfile.c_str(), ios::out | ios::binary | ios::trunc);
}

file_wrapper::~file_wrapper() 
{ 
	if (!success) 
		_wremove(tmpfile.c_str()); 
}

void file_wrapper::read(unsigned char* buf, size_t len)
{
	ifile.read((char*)buf, len);
}

void file_wrapper::write(const unsigned char* buf, size_t len)
{
	ofile.write((const char*)buf, len);
}

void file_wrapper::complete() 
{ 
	ifile.close(); 
	ofile.close(); 
	if (_wremove(file.c_str()))
		throw runtime_error("Can't delete original file");
	success = !_wrename(tmpfile.c_str(), file.c_str());
	if (!success)
		throw runtime_error("Can't rename temporary file");
}

long long file_wrapper::file_size() const
{
	struct _stat64 st_stat;

	if (_wstat64(file.c_str(), &st_stat))
		throw runtime_error("Error reading file size");
	
	return st_stat.st_size;
}

bool file_wrapper::file_exists() const
{
	struct _stat64 st_stat;

	return !_wstat64(file.c_str(), &st_stat);
}

bool file_wrapper::is_directory() const
{
	std::wstring spath(file);
	struct _stat64 st_stat;

	spath.erase(spath.find_last_not_of(_T("/\\") + 1));

	if (spath.length() > 1 && *spath.rbegin() == _T(':'))
		spath += _T('/');

	return !_wstat64(spath.c_str(), &st_stat) && (st_stat.st_mode & S_IFDIR);
}



