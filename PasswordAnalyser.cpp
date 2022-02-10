#include "PasswordAnalyser.h"
#define DEBUG 0

PasswordAnalyser::PasswordAnalyser(string filepath, bool overwrite, PassEncryptor* pe) : FileHandler(filepath, overwrite), pe(pe)
{
	passwords = new string * [20000]{ nullptr }; // non contiguous

	passwords[0] = new string[50];

	srand((unsigned int)time(NULL));

	while (validChars.size() < 10) {
		int x = rand() % 26 + 97;
		validChars.insert(x);
	}

	if (!overwrite) {
		ReadInPasswords();
	}
}

PasswordAnalyser::~PasswordAnalyser()
{
	for (int i = 0; i < 20000; i++) {
		if (passwords[i])
			delete passwords[i];
	}
	delete[] passwords;
	passwords = nullptr;
	pe = nullptr;
}

void PasswordAnalyser::ReadInPasswords()
{
	string pass;
	string* x;
	int i = 0;
	passFile.clear();
	passFile.seekg(ios::beg);
	while (getline(passFile, pass)) {
		x = new string();
		*x = pass;
		passwords[i] = x;
		i++;
		x = nullptr;
	}
}

void PasswordAnalyser::PrintPasswords() {
	for (int i = 0; i < 20000; i++) {
		if (passwords[i])
			cout << *(passwords[i]) << endl;
	}
}

void PasswordAnalyser::GeneratePasswords()
{
	passFile.clear();
	passFile.seekg(ios::beg);
	if (!(passFile.peek() == std::fstream::traits_type::eof())) {
		ClearFile();
	}

	int length;

	for (int i = 0; i < 10000; i++) {
		length = (i / 100) + 1;
		passwords[i] = GenerateRepetitivePass(length);
		passwords[10000 + i] = GenerateNonRepetitivePass(length);
	}

	for (int i = 0; i < 20000; i++) {
		if (passwords[i])
			passFile << *passwords[i] << "\n";
	}
}

void PasswordAnalyser::ClearFile()
{
	// Close and reopen file, clearing it in the process
	passFile.close();
	auto options = ios::out | ios::in | ios::trunc;
	passFile.open(filepath, options);

	// Delete all passwords in memory
	for (int i = 0; i < 20000; i++) {
		if (passwords[i])
			delete passwords[i];
	}
}

string* PasswordAnalyser::GenerateRepetitivePass(int length)
{
	vector<int> password;

	for (int i = 0; i < length; i++) {
		auto it = validChars.begin();
		advance(it, rand() % validChars.size());
		password.emplace_back(*it);
	}

	string* x = new string();
	*x = pe->EncryptPass(password);

	return x;
}

string* PasswordAnalyser::GenerateNonRepetitivePass(int length)
{
	vector<int> password;

	while (password.size() < length) {
		int x = (rand() % 255) + 1;
		if (find(password.begin(), password.end(), x) == password.end()) {
			password.emplace_back(x);
		}
	}

	string* x = new string();
	*x = pe->EncryptPass(password);

	return x;
}

bool PasswordAnalyser::GetAllPasswords(string password)
{
	bool success = false;
	vector<vector<int>> decryptedPasswords;
	vector<int> decrypted;
	success = BruteForce(decryptedPasswords, decrypted, password, success);
#if DEBUG
	cout << "Number of possible passwords: " << decryptedPasswords.size() << endl;
#endif
	return success;
}

bool PasswordAnalyser::BruteForce(vector<vector<int>>& decryptedPasswords, vector<int>& decrypted, string remaining, bool& success, int offset) {
	if (remaining.length() == 0) {
		decryptedPasswords.emplace_back(decrypted);
		success = true;
		return success;
	}

	for (int i = lowerBound; i < upperBound; i++) {
		int x = pe->CollatzConjecture(i + offset);
		if (x == stoi(remaining.substr(0, to_string(x).length()))) {
			decrypted.emplace_back(i);
			BruteForce(decryptedPasswords, decrypted, remaining.substr(to_string(x).length()), success, x);
			decrypted.pop_back();
		}
	}
	return success;
}

/*
decrypted = decrypted password string built up over time
remaining = remaining piece of hashed password
*/
void PasswordAnalyser::DecryptPassword(vector<int>& decrypted) {
	int offset = 0;
	int count = 0;
	for (int x : decrypted) {
		for (int i = lowerBound; i < upperBound; i++) {
			int n = pe->CollatzConjecture(i + offset);

			if (n == x) {
				offset = x;
				decrypted.at(count) = i;
				count++;
				break;
			}
		}
	}
}

bool PasswordAnalyser::GenerateFirstViablePath(vector<int>& decrypted, string remaining, int offset)
{
	bool result = false;

	if (remaining.length() == 0) {
		return true;
	}

	// Generate ASCII values with given offset
	set<int> possibleValues;
	for (int i = lowerBound; i < upperBound; i++) {
		int x = pe->CollatzConjecture(i + offset);
		possibleValues.insert(x);
	}

	// Go through ASCII values and see if they match
	for (auto it = possibleValues.rbegin(); it != possibleValues.rend(); it++) {
		string test = to_string(*it);
		if (test == remaining.substr(0, test.length())) {
			decrypted.emplace_back(*it);
			result = GenerateFirstViablePath(decrypted, remaining.substr(test.length()), stoi(remaining.substr(0, test.length())));

			if (result)
				break;
			decrypted.pop_back();
		}
	}

	return result;
}

/*
Returns number of possible passwords
*/
bool PasswordAnalyser::SmartDecrypt(string password)
{
	bool success = false;
	vector<int> test;
	vector<vector<int>> combinations;
	success = GenerateViablePaths(combinations, test, password, success, false);
	CalculateNumberPasswords(combinations);

	return success;
}

/*
Returns first password cracked
*/
bool PasswordAnalyser::Decrypt(string password)
{
	vector<int> decrypted;
	bool success = GenerateFirstViablePath(decrypted, password);
	DecryptPassword(decrypted);
#if DEBUG
	for (auto x : decrypted) {
		cout << char(x);
	} cout << endl;
#endif
	return success;
}

/*
Goes through password and tests to see if encrypted ASCII characters match with encrypted password
Creates a list of all viable paths through the encrypted password
*/
bool PasswordAnalyser::GenerateViablePaths(vector<vector<int>>& viablePaths, vector<int>& path, string password, bool& success, bool sentence, int offset)
{

	if (password.length() == 0) {
		viablePaths.emplace_back(path);
		success = true;
		return success;
	}

	// Generate ASCII values with given offset
	set<int> possibleValues;

	for (int i = lowerBound; i < upperBound; i++) {
		if (sentence) {

			if (i > 32 && i < 65) {
				continue;
			}
		}
		int x = pe->CollatzConjecture(i + offset);
		possibleValues.insert(x);
	}

	// Go through ASCII values and see if they match
	for (auto it = possibleValues.rbegin(); it != possibleValues.rend(); it++) {
		string test = to_string(*it);

		if (test == password.substr(0, test.length())) {
			path.emplace_back(*it);
			GenerateViablePaths(viablePaths, path, password.substr(test.length()), success, sentence, stoi(password.substr(0, test.length())));
			path.pop_back();
		}
	}

	return success;
}

/*
Given the possible combinations of letters, calculate the number of passwords that could be used
*/
void PasswordAnalyser::CalculateNumberPasswords(vector<vector<int>>& combinations)
{
	vector<int> totalNumberOfPasswords(1, 0);
	for (auto x : combinations) {
		int offset = 0;

		vector<int> numberOfLetters;

		for (int i = 0; i < x.size(); i++) {
			numberOfLetters.emplace_back(0);
			for (int j = lowerBound; j < upperBound; j++) {
				if (pe->CollatzConjecture(j + offset) == x[i]) {
					numberOfLetters[i]++;
				}
			}
			offset = x[i];
		}

		vector<int> totalNumber(1, 1);
		int bigNumber = 1;

		for (int x : numberOfLetters) {
			MultiplyBigInteger(totalNumber, x);
		}
		AddBigInteger(totalNumberOfPasswords, totalNumber);
	}
}

void PasswordAnalyser::MultiplyBigInteger(vector<int>& bigInteger, int mult)
{
	int carry = 0;
	for (vector<int>::reverse_iterator i = bigInteger.rbegin(); i != bigInteger.rend(); i++) {

		int result = (*i) * mult;
		result += carry;

		*i = result % 10;
		carry = result / 10;
	}

	if (carry > 0) {
		bigInteger.emplace(bigInteger.begin(), carry);
	}
}

void PasswordAnalyser::AddBigInteger(vector<int>& left, vector<int>& right)
{
	if (right.size() > left.size()) {
		size_t difference = right.size() - left.size();
		for (int i = 0; i < difference; i++) {
			left.insert(left.begin(), 0);
		}
	}

	if (left.size() > right.size()) {
		size_t difference = left.size() - right.size();
		for (int i = 0; i < difference; i++) {
			right.insert(right.begin(), 0);
		}
	}

	int carry = 0;
	for (int i = static_cast<int>(left.size()) - 1; i >= 0; i--) {
		left[i] += carry;
		int result = left[i] + right[i];
		left[i] = result % 10;
		carry = result / 10;
	}

	if (carry > 0) {
		left.emplace(left.begin(), carry);
	}
}

void PasswordAnalyser::DecryptSentence(string password)
{
	// Try opening a file
	cout << "Opening file... ";
	ifstream file;
	vector<string>* dict = new vector<string>();
	try {
		file.open("english.txt");
		string str;
		while (getline(file, str)) {
			(*dict).emplace_back(str);
		}
	}
	catch (exception e) {
		cout << "Could not open file \"english.txt\"" << endl;
		return;
	}
	cout << "Done!" << endl;

	lowerBound = 32;
	upperBound = 127;

	cout << "Generating paths... ";
	// Generate path through password
	vector<vector<int>> viablePaths;
	vector<int> path;
	bool success = false;

	success = GenerateViablePaths(viablePaths, path, password, success, true);

	cout << "Done!" << endl;
	cout << "Checking possible letters... ";
	int offset = 0;

	// Turn path into possible words
	vector<vector<char>> currentWord;
	int currentLetter = 0;

	vector<vector<string>> possibleWordsInSentence;

	for (int x : viablePaths[0]) {
		vector<char> currentLetterVector;
		for (int i = 32; i < 123; i++) {
			if (i > 32 && i < 65)
				continue;
			if (pe->CollatzConjecture(i + offset) == x) {
				if (i == 32) {
					vector<char> word;
					vector<string> possibleWords;
					CreateWords(currentWord, word, dict, possibleWords, true);
					possibleWordsInSentence.emplace_back(possibleWords);
					currentLetter = 0;
					currentWord.clear();
				}
				else
					currentLetterVector.emplace_back(char(i));
			}

		}
		if (currentLetterVector.size() > 0) {
			currentWord.emplace_back(currentLetterVector);
			currentLetter++;
		}
		offset = x;
	}
	cout << "Done!" << endl;
	cout << "Turning letters into words... ";
	vector<char> word;
	vector<string> possibleWords;
	CreateWords(currentWord, word, dict, possibleWords, true);
	possibleWordsInSentence.emplace_back(possibleWords);

	cout << "Done!" << endl;
	cout << "Turning words into sentences... ";
	vector<string> result;
	vector<string> curWord;
	CreateWords(possibleWordsInSentence, curWord, dict, result, false);
	cout << "Done!\n========== RESULTS ==========" << endl;
	for (auto x : result) {
		cout << x << endl;
	}
	cout << "=============================" << endl;
	lowerBound = 1;
	upperBound = 255;
}

