#include "FileHandler.h"
#pragma warning(disable : 4290)

FileHandler::FileHandler(string filepath, bool overwrite) throw (invalid_argument) : filepath(filepath)
{
	try {
		auto options = ios::out | ios::in;

		if (overwrite)
			options |= ios::trunc;
		else
			options |= ios::app;

		passFile.open(filepath, options);
		if (passFile.fail())
			throw invalid_argument("Unable to open or create file: " + filepath);
	}
	catch (exception e) {
		cout << "Could not open file at: " << filepath << endl;
	}
}

FileHandler::~FileHandler()
{
	passFile.close();
}

void FileHandler::WriteFile(string record)
{
	passFile.clear();
	passFile.seekg(ios::end);
	passFile << record << "\n";
}

void FileHandler::CloseFile()
{
	passFile.close();
}


