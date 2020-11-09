//Шифр RC5 
//Санников Руслан, гр. ИТ-41

#include <cstring>
#include <iostream>
#include <cstdlib>
#include <string>
#include <iomanip>

using namespace std;

template <class WORD> class RC5
{
public:
	RC5(int r, int keyLength, const unsigned char* keyData);
	~RC5();
	void Encrypt(const WORD* in, WORD* out);
	void Decrypt(const WORD* in, WORD* out);
private:
	//RC5-W/R/b
	int w; //половина длины блока в битах
	int r; //число раундов
	int b; //длина ключа в байтах
	int c; 
	int sTableSize; //таблица размер
	WORD* S; //таблица расширенных ключей
	WORD P; //константа
	WORD Q; //константа
	void KeyIninitialize(const unsigned char* keyData);
	WORD CyclicRightShift(WORD x, WORD y); //цикличесукий сдвиг вправл х на у бит
	WORD CyclicLeftShift(WORD x, WORD y); //цикличесукий сдвиг влево х на у бит
};

template<class WORD>
RC5<WORD>::RC5(int r, int keyLength, const unsigned char* keyData)
{
	w = sizeof(WORD) * 8; //u = W/8 => W = u*8
	b = keyLength;
	c = b * 8 / w; //c = b/u => c = (b*8)/W
	sTableSize = 2 * (r + 1); //формирование подключей
	//Qw<-Odd((exp-2)*2^w)
	//Pw<-Odd((exp-2)*2^w)
	switch (sizeof(WORD))
	{
	case 2:
		P = (WORD)0xb7e1; //P(16) = 1011011111100001(2) = B7E1(16)
		Q = (WORD)0x9e37; //Q(16) = 1011011111100001(2) = 9E37(16)
		break;
	case 4:
		P = (WORD)0xb7e15163; //P(32) = 10110111111000010101000101100011(2) = B7E15163(16)
		Q = (WORD)0x9e3779b9; //Q(32) = 10011110001101110111100110111001(2) = 9E3779B9(16)
		break;
	case 8:
		P = (WORD)0xb7e151628aed2a6b; //P(64) = B7E151628AED2A6B(16)
		Q = (WORD)0x9e3779b97f4a7c15; //P(64) = 9E3779B97F4A&C15(16)
		break;
	default:
		break;
	}
	S = new WORD[sTableSize];
	KeyIninitialize(keyData);
}
template<class WORD>
RC5<WORD>::~RC5()
{
	delete[] S;
}
template<class WORD>
void RC5<WORD>::Encrypt(const WORD* pt, WORD* ct)
{
	int i;
	WORD A = pt[0] + S[0], B = pt[1] + S[1];
	for (i = 1; i <= r; i++)
	{
		A = CyclicLeftShift((WORD)(A ^ B), B) + S[2 * i];
		B = CyclicLeftShift((WORD)(B ^ A), A) + S[2 * i + 1];
	}
	ct[0] = A;
	ct[1] = B;
}
template<class WORD>
void RC5<WORD>::Decrypt(const WORD* ct, WORD* pt)
{
	int i;
	WORD B = ct[1], A = ct[0];
	for (i = r; i > 0; i--)
	{
		B = CyclicRightShift(B - S[2 * i + 1], A) ^ A;
		A = CyclicRightShift(A - S[2 * i], B) ^ B;
	}
	pt[1] = B - S[1];
	pt[0] = A - S[0];
}
template<class WORD>
void RC5<WORD>::KeyIninitialize(const unsigned char* keyData)
{
	int i, j, k;
	WORD A, B;
	WORD u = w / 8;
	WORD* L = new WORD[c];
	memset(L, 0, sizeof(L));
	for (i = b - 1; i != -1; i--)
		L[i / u] = (L[i / u] << 8) + keyData[i];
	for (i = 1, S[0] = P; i < sTableSize; i++)
		S[i] = S[i - 1] + Q;
	for (A = B = i = j = k = 0; k < 3 * sTableSize; k++)
	{
		A = S[i] = CyclicLeftShift(S[i] + (A + B), 3);
		B = L[j] = CyclicLeftShift(L[j] + (A + B), A + B);
		i = (i + 1) % sTableSize;
		j = (j + 1) % c;
	}
	delete[] L;
}

template<class WORD>
WORD RC5<WORD>::CyclicRightShift(WORD x, WORD y)
{
	return (x >> (y & (w - 1))) | (x << (w - (y & (w - 1))));
}

template<class WORD>
WORD RC5<WORD>::CyclicLeftShift(WORD x, WORD y)
{
	return (x << (y & (w - 1))) | (x >> (w - (y & (w - 1))));
}

int main()
{
	setlocale(LC_ALL, "Rus");
	const unsigned char key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	RC5<unsigned short> rc5(32, 12, key);
	int enter;
	unsigned int in;
	while (true)
	{
		cout << "Введите 1 для шифрования или 2 для расшифровки" << endl;
		cin >> enter;
		switch (enter)
		{
		case 1:
		{
			cout << "Сообщение:  " << endl;
			cin >> in;
			unsigned short pt[2];
			unsigned short ct[2];
			pt[0] = (unsigned short)in;
			pt[1] = (unsigned short)(in >> 16);
			rc5.Encrypt(pt, ct);
			unsigned int out;
			out = ((unsigned int)ct[0]) | ((unsigned int)(ct[1]) << 16);
			cout << "Засшифровка: 0x" << hex << setfill('0') << setw(8) << out << endl;
			break;
		}
		case 2:
		{
			cout << "Сообщение:  " << endl;
			cin >> hex >> in;
			unsigned short pt[2];
			unsigned short ct[2];
			ct[0] = (unsigned short)in;
			ct[1] = (unsigned short)(in >> 16);
			rc5.Decrypt(ct, pt);
			unsigned int out;
			out = ((unsigned int)pt[0]) | ((unsigned int)(pt[1]) << 16);
			cout << "Расшифровка: " << dec << out << endl;
			break;
		}
		}
		if (enter != 1 && enter != 2)
		{
			cout << "Неверно! Введите 1 или 2" << endl;
		}
	}
	system("pause");
	return 0;
}