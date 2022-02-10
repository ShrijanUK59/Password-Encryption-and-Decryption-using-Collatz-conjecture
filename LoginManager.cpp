#include "LoginManager.h"

LoginManager::LoginManager(string filepath, bool overwrite, PassEncryptor* pe) : FileHandler(filepath, overwrite), pe(pe) {
	passFile.clear();
	passFile.seekg(ios::beg);

	string text;
	size_t split;

	while (getline(passFile, text)) {
		split = text.find(' ');
		logins.insert(pair<string, string>(text.substr(0, split), text.substr(split + 1)));
	}
}

LoginManager::~LoginManager()
{
	pe = nullptr;
}

bool LoginManager::CheckFile(login l)
{
	auto index = logins.find(l.username);
	if (index->second == l.password)
		return true;

	return false;
}

string LoginManager::AddLogin(login l)
{
	if (logins.find(l.username) != logins.end())
		return "User already exists.";

	WriteFile(l.username + " " + l.password);
	logins.insert(pair<string, string>(l.username, l.password));
	return "User created.";
}

bool LoginManager::AttemptLogin(login& l) {

	int tries = 3;

	while (tries > 0) {
		cout << tries << " remaining.\n";
		genLogin(l);
		if (CheckFile(l)) {
			cout << "Successfully logged in.\n";
			return true;
		}
		cout << "Username or Password incorrect.\n";
		tries--;
	}

	cout << "Ran out of tries.\n";
	return false;
}

void LoginManager::genLogin(login& l) {

	cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

	string username;
	string password;

	while (true) {
		cout << "Enter username: ";
		getline(cin, username);

		if (username.find(' ') == string::npos) {
			break;
		}

		cout << "Username cannot contain spaces." << endl;
	}

	cout << "Enter password: ";
	getline(cin, password);

	l.username = username;
	l.password = pe->EncryptPass(password);
}