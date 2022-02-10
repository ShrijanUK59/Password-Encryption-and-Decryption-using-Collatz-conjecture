#include "PassEncryptor.h"

string PassEncryptor::EncryptPass(string passPlain) const
{
	int offset = 0;
	string password = "";

	for (char c : passPlain) {
		offset = CollatzConjecture(c + offset);
		password += to_string(offset);
	}

	return (password);
}

string PassEncryptor::EncryptPass(vector<int> passPlain) const
{
	int offset = 0;
	string password = "";

	for (int c : passPlain) {
		offset = CollatzConjecture(c + offset);
		password += to_string(offset);
	}

	return (password);
}

int PassEncryptor::CollatzConjecture(int n, int count) const
{
	if (n == 1)
		return count;

	count++;
	n % 2 == 0 ? CollatzConjecture(n / 2, count) : CollatzConjecture(3 * n + 1, count);
}
