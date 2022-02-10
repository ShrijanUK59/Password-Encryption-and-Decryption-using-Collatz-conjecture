#include <iostream>
#include "PassEncryptor.h"
#include "PasswordAnalyser.h"
#include "PasswordAnalyserManager.h"
#include "LoginManager.h"
#include <vector>
#include <algorithm>
#include <map>
#include <unordered_map>
#include <chrono>

using namespace std;

inline void printMenu() {
	cout << "\n\nPlease pick an option from the following:" << endl;
	cout << "\n\n1. Create username and password\n"
		<< "\n\n2. Check username and password\n"
		<< "\n\n3. Generate password strength analysis file\n"
		<< "\n\n4. Analyse password strength analysis file\n"
		<< "\n\n5. Decrypt Sentence\n"
		<< "\n0. Exit"
		<< "\n> ";
};

int main()
{
	PassEncryptor pe;
	LoginManager lm("passwords.txt", false, &pe);
	PasswordAnalyserManager pm("passwordtest.txt", false, &pe);

	login log;
	int option = -1;

	while (option != 0) {
		printMenu();
		cin >> option;

		switch (option) {
		case 1:
			lm.genLogin(log);
			cout << lm.AddLogin(log);
			break;
		case 2:
			cout << (lm.AttemptLogin(log) ? "Success" : "Failure") << endl;
			break;
		case 3:
			pm.GeneratePasswords();
			break;
		case 4:
			pm.Menu();
			break;
		case 5:
			pm.DecryptSentence("27322810313331033910211452912207344136146925461033281533271031012815108114101");
			break;
		}
	}
}