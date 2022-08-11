
#ifndef CRYPTOR_FILEWRAPPER_H
#define CRYPTOR_FILEWRAPPER_H

class file_wrapper
{
public:
	file_wrapper(const std::wstring& filename);
	~file_wrapper();
	void read(unsigned char* buf, size_t len);
	void write(const unsigned char* buf, size_t len);
	void complete();
	long long file_size() const;
	bool file_exists() const;
	bool is_directory() const;

private:
	std::wstring file;
	std::wstring tmpfile;
	std::ofstream ofile;
	std::ifstream ifile;
	bool success;
};


#endif

