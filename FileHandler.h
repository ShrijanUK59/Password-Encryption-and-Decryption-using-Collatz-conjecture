#pragma once
#pragma warning(disable : 4290)
#include <string>
#include <fstream>
#include <map>
#include <iostream>
#include <stdexcept>
using namespace std;

class FileHandler {
public:
	FileHandler(string, bool) throw (invalid_argument);
	virtual ~FileHandler();
	void WriteFile(string);
	void CloseFile();

protected:
	string filepath;
	fstream passFile;
	map<string, string> logins;
};
