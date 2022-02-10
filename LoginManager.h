#pragma once
#include "FileHandler.h"
#include "PassEncryptor.h"

using namespace std;

struct login {
	string username;
	string password;
};

class LoginManager : public FileHandler {
public:
	LoginManager(string, bool, PassEncryptor*);
	virtual ~LoginManager();

	bool CheckFile(login l);
	string AddLogin(login l);

	bool AttemptLogin(login& l);

	void genLogin(login& l);

private:
	map<string, string> logins;
	PassEncryptor* pe;
};