#pragma once
#include <string>
#include <vector>

using namespace std;

class PassEncryptor {
public:
	string EncryptPass(string passPlain) const;
	string EncryptPass(vector<int> passPlain) const;
	int CollatzConjecture(int n, int count = 0) const;
};