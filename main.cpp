#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>

#include <openssl/evp.h>

std::string computeHash(const std::string& filename, const std::string& type);
std::string convertToString(char* a, int size);

int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "Russian");
    std::string file_name;
    std::string hash_type;
    std::string hash;
    std::ifstream in(argv[1]);
    const std::string files_path = argv[2];
    if (in.is_open())
    {
        while (!in.eof())
        {
            in >> file_name >> hash_type >> hash;
            std::string new_hash = computeHash(files_path + "\\" + file_name, hash_type);
            if (hash != new_hash)
            {
                if (new_hash == "NOT FOUND")
                    std::cout << file_name + " NOT FOUND" << std::endl;
                else
                    std::cout << file_name + " FAILED" << std::endl;
            }
            else
            {
                std::cout << file_name + " OK" << std::endl;
            }
        }
    }
    in.close();

	return 0;
}

std::string computeHash(const std::string& file, const std::string& type)
{
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md;
    unsigned char output[EVP_MAX_MD_SIZE];
    unsigned int output_len;
    char final[EVP_MAX_MD_SIZE * 2 + 1];
    std::string result;
    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname(type.c_str());

    if (!md) 
    {
        result = "Wrong digest";
        return result;

    }

    EVP_MD_CTX_init(mdctx);
    EVP_DigestInit_ex(mdctx, md, NULL);
    std::ifstream is(file, std::ifstream::binary);

    if (!is)
    {
        result = "NOT FOUND";
        return result;
    }

    is.seekg(0, is.end);
    int length = is.tellg();
    is.seekg(0, is.beg);
    char* buffer = new char[length];

    is.read(buffer, length);

    if(!is)
        std::cout << "error: only " << is.gcount() << " could be read";

    EVP_DigestUpdate(mdctx, buffer, length);
    EVP_DigestFinal_ex(mdctx, output, &output_len);

    for (int i = 0; i < output_len; ++i)
         sprintf(final+i*2, "%02X", output[i]);

    result = convertToString(final, EVP_MAX_MD_SIZE * 2 + 1);

    EVP_MD_CTX_free(mdctx);
    is.close();
    delete[] buffer;
    return result;
}

std::string convertToString(char* a, int size)
{
    int i = 0;
    std::string s = "";
    while(a[i] != '\0')
    {
        s = s + a[i];
        ++i;
    }
    return s;
}
