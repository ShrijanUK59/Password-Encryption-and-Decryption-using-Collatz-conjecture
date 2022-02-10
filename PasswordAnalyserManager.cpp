#include "PasswordAnalyserManager.h"

PasswordAnalyserManager::PasswordAnalyserManager(string filepath, bool overwrite, PassEncryptor* pe) : PasswordAnalyser(filepath, overwrite, pe)
{
}

PasswordAnalyserManager::~PasswordAnalyserManager()
{
}

inline void PasswordAnalyserManager::PrintMenu()
{
	cout << "\nPassword Cracker Menu: " << endl;
	cout << "1. Brute Force (Very Slow)\n"
		<< "2. Calculate Number of Possible Passwords (Slow)\n"
		<< "3. Test Passwords\n"
		<< "4. Restrict Range\n"
		<< "\n0. Exit"
		<< "\n> ";
}

void PasswordAnalyserManager::Menu()
{
	params p;

	auto getParams = [&p, this](int lowerLimit, int upperLimit, bool set) {
		cout << "Lower Bound: " << lowerBound << " | Upper Bound: " << upperBound << endl;
		if (set) {
			while (true) {
				cout << "Which set would you like to use?\nSet 1 - 10 Chars, Repeated.\nSet 2 - Non Repeated, Extended ASCII set.\n> ";
				cin >> p.set;

				if (p.set == 1 || p.set == 2)
					break;
				else
					cout << "Invalid input, please try again." << endl;
			}
		}


		while (true) {

			cout << "Please input starting char length\n> ";
			cin >> p.start;

			cout << "Please input finishing char length\n> ";
			cin >> p.end;

			if (p.end >= p.start && p.start >= lowerLimit && p.end <= upperLimit)
				break;
			else
				cout << "Invalid input, please try again." << endl;
		}
	};

	decryptMethodPtr fncPtr;

	int option = -1;
	while (option != 0) {
		PrintMenu();
		cin >> option;

		switch (option) {
		case 1:
			fncPtr = &PasswordAnalyser::GetAllPasswords;
			getParams(1, 100, true);
			TestMethod(fncPtr, p);
			break;
		case 2:
			fncPtr = &PasswordAnalyser::SmartDecrypt;
			getParams(1, 100, true);
			TestMethod(fncPtr, p);
			break;
		case 3: {

			fncPtr = &PasswordAnalyser::Decrypt;
			getParams(1, 100, true);
			TestMethod(fncPtr, p);
			break;
		}
		case 4:
			getParams(1, 255, false);
			lowerBound = p.start;
			upperBound = p.end;
			break;
		}
	}
}

void PasswordAnalyserManager::TestMethod(decryptMethodPtr t, params p)
{
	for (int i = p.start; i <= p.end; i++) {
		double categoryAverage = 0;
		int success = 0;
		for (int j = 0; j < 100; j++) {
			bool s = false;
			string password = *passwords[(10000 * (p.set - 1)) + ((i - 1) * 100) + j];
			auto t1 = chrono::high_resolution_clock::now();
			s = (this->*t)(password);
			auto t2 = chrono::high_resolution_clock::now();

			chrono::duration<double, std::milli> millis = t2 - t1;
			categoryAverage += millis.count();
			if (s)
				success++;
		}

		printf("Average for %3d chars: %.3fms\t|  Success Rate: %.2f", i, categoryAverage / 100.0, (success / 100.0) * 100.0);
		cout << "%\n";
	}
}