#pragma once
#include "PassAnalyserError.h"
#include "FileHandler.h"
#include "PassEncryptor.h"
#include <vector>
#include <time.h>
#include <set>
#include <stdlib.h>
#include <algorithm>

using namespace std;

class PasswordAnalyser : public FileHandler {
public:
	PasswordAnalyser(string, bool, PassEncryptor*);
	virtual ~PasswordAnalyser();

	void ReadInPasswords();

	void GeneratePasswords();
	void ClearFile();
	void PrintPasswords();

	string* GenerateRepetitivePass(int length);
	string* GenerateNonRepetitivePass(int length);

	bool GetAllPasswords(string password);
	bool BruteForce(vector<vector<int>>& decryptedPasswords, vector<int>& decrypted, string remaining, bool& success, int offset = 0);

	void DecryptPassword(vector<int>& decrypted);
	bool GenerateFirstViablePath(vector<int>& decrypted, string remaining, int offset = 0);

	bool SmartDecrypt(string password);
	bool Decrypt(string password);

	bool GenerateViablePaths(vector<vector<int>>& viablePaths, vector<int>& path, string password, bool& success, bool sentence, int offset = 0);
	void CalculateNumberPasswords(vector<vector<int>>& combinations);

	void MultiplyBigInteger(vector<int>& bigInteger, int mult);
	void AddBigInteger(vector<int>& left, vector<int>& right);

	void DecryptSentence(string password);
	template<typename T>
	void CreateWords(vector<vector<T>> letterList, vector<T>& word, vector<string>* dict, vector<string>& possible, bool checkDict, int currentLetter = 0);

	string getPassword(int index) {
		return *(passwords[index]);
	};

protected:
	string** passwords;
	PassEncryptor* pe;
	set<int> validChars;
	int lowerBound = 1;
	int upperBound = 255;
};

template <typename T>
void PasswordAnalyser::CreateWords(vector<vector<T>> letterList, vector<T>& word, vector<string>* dict, vector<string>& possible, bool checkDict, int currentLetter)
{
	if (word.size() == letterList.size()) {
		string test = "";
		for (auto x : word) {
			test += x;
		}

		if (checkDict) {
			if (find(dict->begin(), dict->end(), test) != dict->end()) {
				possible.emplace_back(test + " ");
			};
		}
		else {
			possible.emplace_back(test);
		}
		return;
	}

	for (T x : letterList.at(currentLetter)) {
		word.emplace_back(x);
		CreateWords(letterList, word, dict, possible, checkDict, currentLetter + 1);
		word.pop_back();
	}
}

