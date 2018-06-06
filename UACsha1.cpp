// UACsha1.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "conio.h"
#include "math.h"
#include "string.h"
#include "stdlib.h"
#include <Windows.h>  
#include "fstream"
#include <string>

#include<iostream>

using namespace std;

const int BIT_FIELD_SIZE = 32;
const int BIT_FIELD_INTMIN = 1 << 31;
const int AES_ENCRYPTION_NB = 4;
const int AES_ENCRYPTION_NK = 5;
const int AES_ENCRYPTION_NR = 11;
const int AES_ENCRYPTION_NKS = AES_ENCRYPTION_NB * (AES_ENCRYPTION_NR + 1);
const string ASCII_UTIL_ASCIIMAP = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF";
const string ASCII_UTIL_BASE64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

typedef unsigned char byte;
typedef int bit_field_array_t[BIT_FIELD_SIZE];
typedef int sha1_hasher_hash_t[5];
typedef sha1_hasher_hash_t imperial_bank_key_t;
typedef int sha1_hasher_block_t[16];
typedef int aes_encryption_key_t[AES_ENCRYPTION_NK];
typedef int aes_encryption_block_t[AES_ENCRYPTION_NB];
typedef byte aes_encryption_table_t[256];

string makeibduac="";
string makeibhhead="";



typedef int bank;

	string ibduac_s;
	char ibduac[200];
	string ibhid_s;
	char ibhid[200];
	string head_s;
	char head[200];


struct bit_field_t{
    
    bit_field_array_t field;
    int pos;
 
    int len;
    
    bool def;
};
struct imperial_bank_ownerref_t{
    int pos; 
    int len; 
};

struct imperial_bank_t{
    
  
    string owners;
    imperial_bank_key_t key;
 
    int savenum; 
  
    int blocknum; 
 
    int loadowner; 
  
    int accountn; 
    imperial_bank_ownerref_t accounts[16];
    bool auth;
};

struct sha1_hasher_t{
    
    sha1_hasher_hash_t h;
};
struct aes_encryption_t{
   
    int keysched[AES_ENCRYPTION_NKS];
   
    int keypos;
};





string ASCII_UTIL_HEXMAP[16];
string ASCIIUtilIntToHex(int in);
int ASCIIUtilStringToInt(string s, int off);
string ASCIIUtilIntToBase64(int in);
int ASCIIUtilBase64ToInt(string s, int off);
// PRIVATE FUNCTIONS
void ASCIIUtilInit();
// IMPLEMENTATION
string ASCIIUtilIntToHex(int in){
    return ASCII_UTIL_HEXMAP[(in >> 28) & 0xF] + ASCII_UTIL_HEXMAP[(in >> 24) & 0xF] + 
        ASCII_UTIL_HEXMAP[(in >> 20) & 0xF] + ASCII_UTIL_HEXMAP[(in >> 16) & 0xF] + 
        ASCII_UTIL_HEXMAP[(in >> 12) & 0xF] + ASCII_UTIL_HEXMAP[(in >> 8) & 0xF] + 
        ASCII_UTIL_HEXMAP[(in >> 4) & 0xF] + ASCII_UTIL_HEXMAP[in & 0xF];
}
int ASCIIUtilStringToInt(string s, int off){
	return ASCII_UTIL_ASCIIMAP.find(s.substr(off-1,1))+1;
}
string ASCIIUtilIntToBase64(int in){
    in+= 1;
	return ASCII_UTIL_BASE64MAP.substr(in-1,1);//StringSub(ASCII_UTIL_BASE64MAP, in, in);
}
int ASCIIUtilBase64ToInt(string s, int off){
    return ASCII_UTIL_BASE64MAP.find(s.substr(off-1,1));
}
void ASCIIUtilInit(){
    int i;
    int j;
    string temp="0123456789ABCDEF";
    i = 0;
    j = 1;
    while( i < 16 ){
		ASCII_UTIL_HEXMAP[i] = temp.substr(j-1,1);
        i = j;
        j+= 1;
    }
}


int bit_field_transformer_t(int in);
void BitFieldInitialize(bit_field_t &obj, int len, bool logic);
void BitFieldResize(bit_field_t &obj, int len);
void BitFieldSetSize(bit_field_t &obj, int len);
int BitFieldGetSize(bit_field_t &obj);
void BitFieldSeek(bit_field_t &obj, int pos);
int BitFieldGetPosition(bit_field_t &obj);
int BitFieldRemaining(bit_field_t &obj);
void BitFieldWrite(bit_field_t &obj, int val, int len);
void BitFieldWriteSafe(bit_field_t &obj, int val, int len);
void BitFieldSet(bit_field_t &obj, int val, int pos);
int BitFieldRead(bit_field_t &obj, int len);
int BitFieldReadSafe(bit_field_t &obj, int len);
int BitFieldGet(bit_field_t &obj, int pos);
void BitFieldTransform(bit_field_t &obj, int (*transformer)(int));
// IMPLEMENTATION

void BitFieldInitialize(bit_field_t &obj, int len, bool logic){
    obj.pos = 0;
    obj.len = 0;
    obj.def = logic;
    BitFieldResize(obj, len);
}
void BitFieldResize(bit_field_t &obj, int len){
    int i;
    int end;
    int val;
    if( len > (BIT_FIELD_SIZE * 32) ){ len = BIT_FIELD_SIZE * 32; }
    else if( len < 0 ){ len = 0; }
  
    if( obj.len > len ){
      
        obj.len = len;
    
        i = len % 32;
        if( i == 0 ){ return; }
        
        end = len / 32;
        val = obj.field[end] & ((1 << i) - 1);
       
        if( obj.def ){
           
            val|= (BIT_FIELD_INTMIN >> (31 - i));
        }
        obj.field[end] = val;
    }
 
    else{
        if( obj.def ){ val = -1; }
        else{ val = 0; }
       
        i = (obj.len + 31) / 32;
        end = (len + 31) / 32;
        
        while( i < end ){
            obj.field[i] = val;
            i+= 1;
        }
     
        obj.len = len;
    }
}
void BitFieldSetSize(bit_field_t &obj, int len){
    obj.len = len;
}
int BitFieldGetSize(bit_field_t &obj){
    return obj.len;
}
void BitFieldSeek(bit_field_t &obj, int pos){
  
    obj.pos = pos;
}
int BitFieldGetPosition(bit_field_t &obj){
    return obj.pos;
}
int BitFieldRemaining(bit_field_t &obj){
    return obj.len - obj.pos;
}
void BitFieldWrite(bit_field_t &obj, int val, int len){
  
    int i;
    int reg;
    int mask;
  
    i = obj.pos % 32;
    reg = obj.pos / 32;
    obj.pos+= len;
   
    mask = ((2 << (len - 1)) - 1) << i; 
    obj.field[reg] = (obj.field[reg] & (~mask)) | ((val << i) & mask);
  
    i = 32 - i;
    if( i >= len ){ return; }
   
    reg+= 1;
  
    mask = (1 << (len - i)) - 1;
    obj.field[reg] = (obj.field[reg] & (~mask)) | ((val >> i) & mask);
}
void BitFieldWriteSafe(bit_field_t &obj, int val, int len){
    
    int i;
  
    if( obj.pos <= -len || obj.pos >= obj.len ){
        obj.pos+= len;
        return;
    }
    
    if( obj.pos < 0 ){
        val>>= -obj.pos;
        len+= obj.pos;
        obj.pos = 0;
    }
   
    i = len + obj.pos - obj.len;
    if( i < 0 ){ i = 0; }
   
    BitFieldWrite(obj, val, len - i);
    obj.pos+= i;
}
void BitFieldSet(bit_field_t &obj, int val, int pos){
    obj.field[pos] = val;
}
int BitFieldRead(bit_field_t &obj, int len){
    
    int i;
    int reg;
    int val;
    
    i = obj.pos % 32;
    reg = obj.pos / 32;
    
    val = obj.field[reg] >> i;
    
    i = 32 - i;
    if( i < len ){ 
       
        val&= (1 << i) - 1;
        
        reg+= 1;
        val|= obj.field[reg] << i;
    }
    
    val&= ((2 << (len - 1)) - 1); 
    obj.pos+= len;
    return val;
}
int BitFieldReadSafe(bit_field_t &obj, int len){
  
    int i = 0;
    int j;
    int val = 0;
  
    if( obj.pos <= -len || obj.pos >= obj.len ){
        obj.pos+= len;
        if( obj.pos ){ return (1 << len) - 1; }
        return 0;
    }
 
    if( obj.pos < 0 ){
        if( obj.def ){ val = (1 << (-obj.pos)) - 1; }
        len+= obj.pos;
        i = -obj.pos;
        obj.pos = 0;
    }
   
    j = len + obj.pos - obj.len;
    if( j <= 0 ){ j = 0; }
    else if( obj.def ){ val|= ((1 << j) - 1) << (len + i - j); }
   
    val|= BitFieldRead(obj, len - j) << i;
    obj.pos+= j;
    return val;
}
int BitFieldGet(bit_field_t &obj, int pos){
    return obj.field[pos];
}
void BitFieldTransform(bit_field_t &obj, int (*transformer)(int)){
    int i = 0;
    int end = obj.len / 32;
    while( i <= end ){
        obj.field[i] = transformer(obj.field[i]);
        i+= 1;
    }
}














//--------------------------------------------------------------------------------------------------
// Custom Script: SHA-1 Hasher
//--------------------------------------------------------------------------------------------------
int sha1_hasher_data_reader_t();

// PUBLIC FUNCTIONS
void SHA1HasherInitalize(sha1_hasher_t &obj);
void SHA1HasherProcess(sha1_hasher_t &obj, sha1_hasher_block_t block);
void SHA1HasherProcessFinal(sha1_hasher_t &obj, sha1_hasher_block_t block, int len);
void SHA1HasherHash(sha1_hasher_t &obj, sha1_hasher_block_t hash);
void SHA1HasherHashData(sha1_hasher_t &obj, int *reader, int len);
// IMPLEMENTATION
void SHA1HasherInitalize(sha1_hasher_t &obj){
  
    obj.h[0] = 0x67452301;
    obj.h[1] = 0x6FCDAB89 | (1 << 31);
    obj.h[2] = 0x18BADCFE | (1 << 31);
    obj.h[3] = 0x10325476;
    obj.h[4] = 0x43D2E1F0 | (1 << 31);
}
void SHA1HasherProcess(sha1_hasher_t &obj, sha1_hasher_block_t block){
    int w[80];
    int i;
    int temp;
    sha1_hasher_hash_t h;
 
    for( i = 0 ; i < 16 ; i+= 1 ){
        
        w[i] = (block[i] << 24) | ((block[i] << 8) & 0xFF0000) | ((block[i] >> 8) & 0xFF00) | ((block[i] >> 24) & 0xFF);
    }
 
    for( ; i < 80 ; i+= 1 ){
        temp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
     
        w[i] = (temp << 1) | ((temp >> 31) & 0x01);
    }
 
    for( i = 0 ; i < 5 ; i+= 1 ){
        h[i] = obj.h[i];
    }
   
    for( i = 0 ; i < 20 ; i+= 1 ){
      
        temp = ((h[0] << 5) | ((h[0] >> 27) & 0x1F)) + ((h[1] & h[2]) | ((~h[1]) & h[3])) + h[4] + 0x5A827999 + w[i];
      
        h[4] = h[3];
        h[3] = h[2];
     
        h[2] = (h[1] << 30) | ((h[1] >> 2) & 0x3FFFFFFF);
        h[1] = h[0];
        h[0] = temp;
    }
 
    for( ; i < 40 ; i+= 1 ){
 
        temp = ((h[0] << 5) | ((h[0] >> 27) & 0x1F)) + (h[1] ^ h[2] ^ h[3]) + h[4] + 0x6ED9EBA1 + w[i];
   
        h[4] = h[3];
        h[3] = h[2];
      
        h[2] = (h[1] << 30) | ((h[1] >> 2) & 0x3FFFFFFF);
        h[1] = h[0];
        h[0] = temp;
    }
  
    for( ; i < 60 ; i+= 1 ){
       
        temp = ((h[0] << 5) | ((h[0] >> 27) & 0x1F)) + ((h[1] & h[2]) | (h[1] & h[3]) | (h[2] & h[3])) + h[4] + (0x0F1BBCDC | (1 << 31)) + w[i];
       
        h[4] = h[3];
        h[3] = h[2];
    
        h[2] = (h[1] << 30) | ((h[1] >> 2) & 0x3FFFFFFF);
        h[1] = h[0];
        h[0] = temp;
    }
    // Process last 20 units.
    for( ; i < 80 ; i+= 1 ){
        //:Left Rotate 5
        temp = ((h[0] << 5) | ((h[0] >> 27) & 0x1F)) + (h[1] ^ h[2] ^ h[3]) + h[4] + (0x4A62C1D6 | (1 << 31)) + w[i];
        // Hash generation logic. Maybe a separate function?
        h[4] = h[3];
        h[3] = h[2];
        //:Left Rotate 30
        h[2] = (h[1] << 30) | ((h[1] >> 2) & 0x3FFFFFFF);
        h[1] = h[0];
        h[0] = temp;
    }
    // Finally append block hashes.
    for( i = 0 ; i < 5 ; i+= 1 ){
        obj.h[i]+= h[i];
    }
}
void SHA1HasherProcessFinal(sha1_hasher_t &obj, sha1_hasher_hash_t block, int len){
    int pos;
    int sub;
    // Determine sub-block position.
    pos = (len % 64) / 4;
    sub = (len % 4) * 8;
    // Append terminator.
    block[pos] = (0x80 << sub) | (block[pos] & ((2 << (sub - 1)) - 1));
    pos+= 1;
    // Determine if another block of padding is needed.
    if( pos > 14 ){
        // Pad block with 0.
        for( ; pos < 16 ; pos+= 1 ){
            block[pos] = 0;
        }
        // Hash block.
        SHA1HasherProcess(obj, block);
        // Start at begining of new block.
        pos = 0;
    }
    // Pad remainder of block with 0.
    for( ; pos < 14 ; pos+= 1 ){
        block[pos] = 0;
    }
    // Append big endian message length (in bits). Cannot support length >268435455 bytes.
    len*= 8;
    block[14] = 0;
    block[15] = (len << 24) | ((len << 8) & 0xFF0000) | ((len >> 8) & 0xFF00) | ((len >> 24) & 0xFF);
    // Hash the last block.
    SHA1HasherProcess(obj, block);
}
void SHA1HasherHash(sha1_hasher_t &obj, sha1_hasher_hash_t hash){
    int i;
    // Bulk copy the hash.
    for( i = 0 ; i < 5 ; i+= 1 ){
        hash[i] = obj.h[i];
    }
}
void SHA1HasherHashData(sha1_hasher_t &obj, int (*reader)(), int len){
    sha1_hasher_block_t block;
    int pos;
    int i;
    // Initalize hasher.
    SHA1HasherInitalize(obj);
    // Whole block read loop.
    pos = 0;
    while( len >= 64 ){
        // Read block.
        for( i = 0 ; i < 16 ; i+= 1 ){
            block[i] = reader();
        }
        // Hash block.
        SHA1HasherProcess(obj, block);
        // Advance.
        pos+= 64;
        len-= 64;
    }
    // Sub-block read.
    for( i = 0 ; i < (len / 4) ; i+= 1 ){
        block[i] = reader();
    }
    pos+= i * 4;
    len-= i * 4;
    // Read sub-int.
    if( len > 0 ){
        block[i] = reader() & ((1 << (8 * len)) - 1);
        pos+= len;
    // Or clear next int.
    }else{
        block[i] = 0;
    }
    // Now work on padding.
    len = pos;
    block[i]|= (0x80 << ((pos % 4) * 8));
    pos = ((pos / 4) + 1) * 4;
    // Determine if another block of padding is needed.
    if( (pos % 64) > 56 ){
        // Pad block with 0.
        for( i = (pos % 64) / 4 ; i < 16 ; i+= 1 ){
            block[i] = 0;
        }
        // Hash block.
        SHA1HasherProcess(obj, block);
        // Advance a block.
        pos = ((pos / 64) + 1) * 64;
    }
    // Pad remainder of block with 0.
    for( i = (pos % 64) / 4 ; i < 14 ; i+= 1 ){
        block[i] = 0;
    }
    // Append big endian message length (in bits). Cannot support length >268435455 bytes.
    i = len * 8;
    block[14] = 0;
    block[15] = (i << 24) | ((i << 8) & 0xFF0000) | ((i >> 8) & 0xFF00) | ((i >> 24) & 0xFF);
    // Hash the last block.
    SHA1HasherProcess(obj, block);
}

//--------------------------------------------------------------------------------------------------
// Custom Script: ASCII Channel
//--------------------------------------------------------------------------------------------------
// TYPES
struct ascii_channel_t{
  
    string buffer;
   
    int pos;
};
// PUBLIC FUNCTIONS
void ASCIIChannelSetup(ascii_channel_t &obj, string s);
int ASCIIChannelLength(ascii_channel_t &obj);
int ASCIIChannelRead(ascii_channel_t &obj);
//
// IMPLEMENTATION
void ASCIIChannelSetup(ascii_channel_t &obj, string s){
    obj.buffer = s;
    obj.pos = 0;
}
int ASCIIChannelLength(ascii_channel_t &obj){
	return obj.buffer.length() - obj.pos;
}
int ASCIIChannelRead(ascii_channel_t &obj){
    int end;
    int shift;
    int val;
    end = obj.pos + 4;
	if( end > obj.buffer.length() ){ end = obj.buffer.length(); }
    
    shift = 0;
    val = 0;
    obj.pos+= 1;
    for( ; obj.pos <= end ; obj.pos+= 1 ){
        val|= ASCIIUtilStringToInt(obj.buffer, obj.pos) << shift;
        shift+= 8;
    }
    obj.pos-= 1;
    return val;
}



//--------------------------------------------------------------------------------------------------
// Custom Script: AES Encryption
//--------------------------------------------------------------------------------------------------

aes_encryption_table_t AES_ENCRYPTION_SBOX;
aes_encryption_table_t AES_ENCRYPTION_ISBOX;
aes_encryption_table_t AES_ENCRYPTION_GM2;
aes_encryption_table_t AES_ENCRYPTION_GM9;
aes_encryption_table_t AES_ENCRYPTION_GM13;
byte AES_ENCRYPTION_RCON[30];


void AESEncryptionSetup(aes_encryption_t &obj, aes_encryption_key_t key);
void AESEncryptionCipher(aes_encryption_t &obj, aes_encryption_block_t block);
void AESEncryptionInvCipher(aes_encryption_t &obj, aes_encryption_block_t block);
int AESEncryptionRotWord(int word);
int AESEncryptionSubWord(int word, aes_encryption_table_t box);
void AESEncryptionSubBytes(aes_encryption_block_t block);
void AESEncryptionShiftRows(aes_encryption_block_t block);
void AESEncryptionMixColumns(aes_encryption_block_t block);
void AESEncryptionAddRoundKey(aes_encryption_t &obj, aes_encryption_block_t block);
void AESEncryptionKeyExpansion(aes_encryption_t &obj, aes_encryption_key_t key);
void AESEncryptionInvShiftRows(aes_encryption_block_t block);
void AESEncryptionInvSubBytes(aes_encryption_block_t block);
void AESEncryptionInvMixColumns(aes_encryption_block_t block);
void AESEncryptionInit();
 
// IMPLEMENTATION
void AESEncryptionSetup(aes_encryption_t &obj, aes_encryption_key_t key){
    AESEncryptionKeyExpansion(obj, key);
}
void AESEncryptionCipher(aes_encryption_t &obj, aes_encryption_block_t block){
    int i;
   
    obj.keypos = 0;
  
    AESEncryptionAddRoundKey(obj, block);
   
    for( i = 1 ; i < AES_ENCRYPTION_NR ; i+= 1 ){
        AESEncryptionSubBytes(block);
        AESEncryptionShiftRows(block);
        AESEncryptionMixColumns(block);
        AESEncryptionAddRoundKey(obj, block);
    }
 
    AESEncryptionSubBytes(block);
    AESEncryptionShiftRows(block);
    AESEncryptionAddRoundKey(obj, block);
}
void AESEncryptionInvCipher(aes_encryption_t &obj, aes_encryption_block_t block){
    int i;
  
    obj.keypos = AES_ENCRYPTION_NKS - AES_ENCRYPTION_NB;
    AESEncryptionAddRoundKey(obj, block);
   
    for( obj.keypos = (AES_ENCRYPTION_NR - 1) * AES_ENCRYPTION_NB ; obj.keypos > 0 ; obj.keypos-= AES_ENCRYPTION_NB * 2 ){
        AESEncryptionInvShiftRows(block);
        AESEncryptionInvSubBytes(block);
        AESEncryptionAddRoundKey(obj, block);
        AESEncryptionInvMixColumns(block);
    }
   
    AESEncryptionInvShiftRows(block);
    AESEncryptionInvSubBytes(block);
    AESEncryptionAddRoundKey(obj, block);
}
int AESEncryptionRotWord(int word){
    return (word << 24) | ((word >> 8) & 0xFFFFFF);
}
int AESEncryptionSubWord(int word, aes_encryption_table_t box){
    int a;
    int tc;
 
    a = box[word & 0xFF];
    tc = box[(word >> 8) & 0xFF];
    a|= tc << 8;
    tc = box[(word >> 16) & 0xFF];
    a|= tc << 16;
    tc = box[(word >> 24) & 0xFF];
    a|= tc << 24;
    return a;
}
void AESEncryptionSubBytes(aes_encryption_block_t block){
  
    block[0] = AESEncryptionSubWord(block[0], AES_ENCRYPTION_SBOX);
    block[1] = AESEncryptionSubWord(block[1], AES_ENCRYPTION_SBOX);
    block[2] = AESEncryptionSubWord(block[2], AES_ENCRYPTION_SBOX);
    block[3] = AESEncryptionSubWord(block[3], AES_ENCRYPTION_SBOX);
}
void AESEncryptionShiftRows(aes_encryption_block_t block){
  
    int a;
    int b;
    int c;
 
    a = (block[0] & 0xFF) | (block[1] & 0xFF00) | (block[2] & 0xFF0000) | (block[3] & ~0xFFFFFF);
    b = (block[1] & 0xFF) | (block[2] & 0xFF00) | (block[3] & 0xFF0000) | (block[0] & ~0xFFFFFF);
    c = (block[2] & 0xFF) | (block[3] & 0xFF00) | (block[0] & 0xFF0000) | (block[1] & ~0xFFFFFF);
    block[3] = (block[3] & 0xFF) | (block[0] & 0xFF00) | (block[1] & 0xFF0000) | (block[2] & ~0xFFFFFF);
    block[2] = c;
    block[1] = b;
    block[0] = a;
}
void AESEncryptionMixColumns(aes_encryption_block_t block){
    int a;
    int b;
  
    a = block[0];
    b = AESEncryptionSubWord(a, AES_ENCRYPTION_GM2);
    block[0] = b ^ ((b << 24) | ((b >> 8) & 0xFFFFFF)) ^ ((a << 24) | ((a >> 8) & 0xFFFFFF)) ^ ((a << 16) | ((a >> 16) & 0xFFFF)) ^ ((a << 8) | ((a >> 24) & 0xFF));
    a = block[1];
    b = AESEncryptionSubWord(a, AES_ENCRYPTION_GM2);
    block[1] = b ^ ((b << 24) | ((b >> 8) & 0xFFFFFF)) ^ ((a << 24) | ((a >> 8) & 0xFFFFFF)) ^ ((a << 16) | ((a >> 16) & 0xFFFF)) ^ ((a << 8) | ((a >> 24) & 0xFF));
    a = block[2];
    b = AESEncryptionSubWord(a, AES_ENCRYPTION_GM2);
    block[2] = b ^ ((b << 24) | ((b >> 8) & 0xFFFFFF)) ^ ((a << 24) | ((a >> 8) & 0xFFFFFF)) ^ ((a << 16) | ((a >> 16) & 0xFFFF)) ^ ((a << 8) | ((a >> 24) & 0xFF));
    a = block[3];
    b = AESEncryptionSubWord(a, AES_ENCRYPTION_GM2);
    block[3] = b ^ ((b << 24) | ((b >> 8) & 0xFFFFFF)) ^ ((a << 24) | ((a >> 8) & 0xFFFFFF)) ^ ((a << 16) | ((a >> 16) & 0xFFFF)) ^ ((a << 8) | ((a >> 24) & 0xFF));
}
void AESEncryptionAddRoundKey(aes_encryption_t &obj, aes_encryption_block_t block){
    block[0]^= obj.keysched[obj.keypos];
    obj.keypos+= 1;
    block[1]^= obj.keysched[obj.keypos];
    obj.keypos+= 1;
    block[2]^= obj.keysched[obj.keypos];
    obj.keypos+= 1;
    block[3]^= obj.keysched[obj.keypos];
    obj.keypos+= 1;
}
void AESEncryptionKeyExpansion(aes_encryption_t &obj, aes_encryption_key_t key){
    int i;
    int temp;
    int conv;
 
    for( i = 0 ; i < AES_ENCRYPTION_NK ; i+= 1 ){
        obj.keysched[i] = key[i];
    }
   
    for( ; i < AES_ENCRYPTION_NKS ; i+= 1 ){
        temp = obj.keysched[i - 1];
        if( (i % AES_ENCRYPTION_NK) == 0 ){
          
            conv = AES_ENCRYPTION_RCON[i / AES_ENCRYPTION_NK];
            temp = AESEncryptionSubWord(AESEncryptionRotWord(temp), AES_ENCRYPTION_SBOX) ^ conv;
        }
        else if( (AES_ENCRYPTION_NK > 6) && ((i % AES_ENCRYPTION_NK) == 4) ){
            temp = AESEncryptionSubWord(temp, AES_ENCRYPTION_SBOX);
        }
        obj.keysched[i] = obj.keysched[i - AES_ENCRYPTION_NK] ^ temp;
    }
}
void AESEncryptionInvShiftRows(aes_encryption_block_t block){
   
    int a;
    int b;
    int c;
   
    a = (block[0] & 0xFF) | (block[3] & 0xFF00) | (block[2] & 0xFF0000) | (block[1] & ~0xFFFFFF);
    b = (block[1] & 0xFF) | (block[0] & 0xFF00) | (block[3] & 0xFF0000) | (block[2] & ~0xFFFFFF);
    c = (block[2] & 0xFF) | (block[1] & 0xFF00) | (block[0] & 0xFF0000) | (block[3] & ~0xFFFFFF);
   
    block[3] = (block[3] & 0xFF) | (block[2] & 0xFF00) | (block[1] & 0xFF0000) | (block[0] & ~0xFFFFFF);
    block[2] = c;
    block[1] = b;
    block[0] = a;
}
void AESEncryptionInvSubBytes(aes_encryption_block_t block){
    block[0] = AESEncryptionSubWord(block[0], AES_ENCRYPTION_ISBOX);
    block[1] = AESEncryptionSubWord(block[1], AES_ENCRYPTION_ISBOX);
    block[2] = AESEncryptionSubWord(block[2], AES_ENCRYPTION_ISBOX);
    block[3] = AESEncryptionSubWord(block[3], AES_ENCRYPTION_ISBOX);
}
void AESEncryptionInvMixColumns(aes_encryption_block_t block){
    int a;
    int b;
    int c;
    int d;
 
    d = block[0];
    a = AESEncryptionSubWord(d, AES_ENCRYPTION_GM9);
    b = a ^ AESEncryptionSubWord(d, AES_ENCRYPTION_GM2);
    c = AESEncryptionSubWord(d, AES_ENCRYPTION_GM13);
    d^= c ^ b ^ a;
    block[0] = d ^ ((b << 24) | ((b >> 8) & 0xFFFFFF)) ^ ((c << 16) | ((c >> 16) & 0xFFFF)) ^ ((a << 8) | ((a >> 24) & 0xFF));
    d = block[1];
    a = AESEncryptionSubWord(d, AES_ENCRYPTION_GM9);
    b = a ^ AESEncryptionSubWord(d, AES_ENCRYPTION_GM2);
    c = AESEncryptionSubWord(d, AES_ENCRYPTION_GM13);
    d^= c ^ b ^ a;
    block[1] = d ^ ((b << 24) | ((b >> 8) & 0xFFFFFF)) ^ ((c << 16) | ((c >> 16) & 0xFFFF)) ^ ((a << 8) | ((a >> 24) & 0xFF));
    d = block[2];
    a = AESEncryptionSubWord(d, AES_ENCRYPTION_GM9);
    b = a ^ AESEncryptionSubWord(d, AES_ENCRYPTION_GM2);
    c = AESEncryptionSubWord(d, AES_ENCRYPTION_GM13);
    d^= c ^ b ^ a;
    block[2] = d ^ ((b << 24) | ((b >> 8) & 0xFFFFFF)) ^ ((c << 16) | ((c >> 16) & 0xFFFF)) ^ ((a << 8) | ((a >> 24) & 0xFF));
    d = block[3];
    a = AESEncryptionSubWord(d, AES_ENCRYPTION_GM9);
    b = a ^ AESEncryptionSubWord(d, AES_ENCRYPTION_GM2);
    c = AESEncryptionSubWord(d, AES_ENCRYPTION_GM13);
    d^= c ^ b ^ a;
    block[3] = d ^ ((b << 24) | ((b >> 8) & 0xFFFFFF)) ^ ((c << 16) | ((c >> 16) & 0xFFFF)) ^ ((a << 8) | ((a >> 24) & 0xFF));
}
void AESEncryptionInit(){
    int i;
    int a;
    byte b;
  
    AES_ENCRYPTION_SBOX[  0] = 0x63;
    AES_ENCRYPTION_SBOX[  1] = 0x7C;
    AES_ENCRYPTION_SBOX[  2] = 0x77;
    AES_ENCRYPTION_SBOX[  3] = 0x7B;
    AES_ENCRYPTION_SBOX[  4] = 0xF2;
    AES_ENCRYPTION_SBOX[  5] = 0x6B;
    AES_ENCRYPTION_SBOX[  6] = 0x6F;
    AES_ENCRYPTION_SBOX[  7] = 0xC5;
    AES_ENCRYPTION_SBOX[  8] = 0x30;
    AES_ENCRYPTION_SBOX[  9] = 0x01;
    AES_ENCRYPTION_SBOX[ 10] = 0x67;
    AES_ENCRYPTION_SBOX[ 11] = 0x2B;
    AES_ENCRYPTION_SBOX[ 12] = 0xFE;
    AES_ENCRYPTION_SBOX[ 13] = 0xD7;
    AES_ENCRYPTION_SBOX[ 14] = 0xAB;
    AES_ENCRYPTION_SBOX[ 15] = 0x76;
    AES_ENCRYPTION_SBOX[ 16] = 0xCA;
    AES_ENCRYPTION_SBOX[ 17] = 0x82;
    AES_ENCRYPTION_SBOX[ 18] = 0xC9;
    AES_ENCRYPTION_SBOX[ 19] = 0x7D;
    AES_ENCRYPTION_SBOX[ 20] = 0xFA;
    AES_ENCRYPTION_SBOX[ 21] = 0x59;
    AES_ENCRYPTION_SBOX[ 22] = 0x47;
    AES_ENCRYPTION_SBOX[ 23] = 0xF0;
    AES_ENCRYPTION_SBOX[ 24] = 0xAD;
    AES_ENCRYPTION_SBOX[ 25] = 0xD4;
    AES_ENCRYPTION_SBOX[ 26] = 0xA2;
    AES_ENCRYPTION_SBOX[ 27] = 0xAF;
    AES_ENCRYPTION_SBOX[ 28] = 0x9C;
    AES_ENCRYPTION_SBOX[ 29] = 0xA4;
    AES_ENCRYPTION_SBOX[ 30] = 0x72;
    AES_ENCRYPTION_SBOX[ 31] = 0xC0;
    AES_ENCRYPTION_SBOX[ 32] = 0xB7;
    AES_ENCRYPTION_SBOX[ 33] = 0xFD;
    AES_ENCRYPTION_SBOX[ 34] = 0x93;
    AES_ENCRYPTION_SBOX[ 35] = 0x26;
    AES_ENCRYPTION_SBOX[ 36] = 0x36;
    AES_ENCRYPTION_SBOX[ 37] = 0x3F;
    AES_ENCRYPTION_SBOX[ 38] = 0xF7;
    AES_ENCRYPTION_SBOX[ 39] = 0xCC;
    AES_ENCRYPTION_SBOX[ 40] = 0x34;
    AES_ENCRYPTION_SBOX[ 41] = 0xA5;
    AES_ENCRYPTION_SBOX[ 42] = 0xE5;
    AES_ENCRYPTION_SBOX[ 43] = 0xF1;
    AES_ENCRYPTION_SBOX[ 44] = 0x71;
    AES_ENCRYPTION_SBOX[ 45] = 0xD8;
    AES_ENCRYPTION_SBOX[ 46] = 0x31;
    AES_ENCRYPTION_SBOX[ 47] = 0x15;
    AES_ENCRYPTION_SBOX[ 48] = 0x04;
    AES_ENCRYPTION_SBOX[ 49] = 0xC7;
    AES_ENCRYPTION_SBOX[ 50] = 0x23;
    AES_ENCRYPTION_SBOX[ 51] = 0xC3;
    AES_ENCRYPTION_SBOX[ 52] = 0x18;
    AES_ENCRYPTION_SBOX[ 53] = 0x96;
    AES_ENCRYPTION_SBOX[ 54] = 0x05;
    AES_ENCRYPTION_SBOX[ 55] = 0x9A;
    AES_ENCRYPTION_SBOX[ 56] = 0x07;
    AES_ENCRYPTION_SBOX[ 57] = 0x12;
    AES_ENCRYPTION_SBOX[ 58] = 0x80;
    AES_ENCRYPTION_SBOX[ 59] = 0xE2;
    AES_ENCRYPTION_SBOX[ 60] = 0xEB;
    AES_ENCRYPTION_SBOX[ 61] = 0x27;
    AES_ENCRYPTION_SBOX[ 62] = 0xB2;
    AES_ENCRYPTION_SBOX[ 63] = 0x75;
    AES_ENCRYPTION_SBOX[ 64] = 0x09;
    AES_ENCRYPTION_SBOX[ 65] = 0x83;
    AES_ENCRYPTION_SBOX[ 66] = 0x2C;
    AES_ENCRYPTION_SBOX[ 67] = 0x1A;
    AES_ENCRYPTION_SBOX[ 68] = 0x1B;
    AES_ENCRYPTION_SBOX[ 69] = 0x6E;
    AES_ENCRYPTION_SBOX[ 70] = 0x5A;
    AES_ENCRYPTION_SBOX[ 71] = 0xA0;
    AES_ENCRYPTION_SBOX[ 72] = 0x52;
    AES_ENCRYPTION_SBOX[ 73] = 0x3B;
    AES_ENCRYPTION_SBOX[ 74] = 0xD6;
    AES_ENCRYPTION_SBOX[ 75] = 0xB3;
    AES_ENCRYPTION_SBOX[ 76] = 0x29;
    AES_ENCRYPTION_SBOX[ 77] = 0xE3;
    AES_ENCRYPTION_SBOX[ 78] = 0x2F;
    AES_ENCRYPTION_SBOX[ 79] = 0x84;
    AES_ENCRYPTION_SBOX[ 80] = 0x53;
    AES_ENCRYPTION_SBOX[ 81] = 0xD1;
    AES_ENCRYPTION_SBOX[ 82] = 0x00;
    AES_ENCRYPTION_SBOX[ 83] = 0xED;
    AES_ENCRYPTION_SBOX[ 84] = 0x20;
    AES_ENCRYPTION_SBOX[ 85] = 0xFC;
    AES_ENCRYPTION_SBOX[ 86] = 0xB1;
    AES_ENCRYPTION_SBOX[ 87] = 0x5B;
    AES_ENCRYPTION_SBOX[ 88] = 0x6A;
    AES_ENCRYPTION_SBOX[ 89] = 0xCB;
    AES_ENCRYPTION_SBOX[ 90] = 0xBE;
    AES_ENCRYPTION_SBOX[ 91] = 0x39;
    AES_ENCRYPTION_SBOX[ 92] = 0x4A;
    AES_ENCRYPTION_SBOX[ 93] = 0x4C;
    AES_ENCRYPTION_SBOX[ 94] = 0x58;
    AES_ENCRYPTION_SBOX[ 95] = 0xCF;
    AES_ENCRYPTION_SBOX[ 96] = 0xD0;
    AES_ENCRYPTION_SBOX[ 97] = 0xEF;
    AES_ENCRYPTION_SBOX[ 98] = 0xAA;
    AES_ENCRYPTION_SBOX[ 99] = 0xFB;
    AES_ENCRYPTION_SBOX[100] = 0x43;
    AES_ENCRYPTION_SBOX[101] = 0x4D;
    AES_ENCRYPTION_SBOX[102] = 0x33;
    AES_ENCRYPTION_SBOX[103] = 0x85;
    AES_ENCRYPTION_SBOX[104] = 0x45;
    AES_ENCRYPTION_SBOX[105] = 0xF9;
    AES_ENCRYPTION_SBOX[106] = 0x02;
    AES_ENCRYPTION_SBOX[107] = 0x7F;
    AES_ENCRYPTION_SBOX[108] = 0x50;
    AES_ENCRYPTION_SBOX[109] = 0x3C;
    AES_ENCRYPTION_SBOX[110] = 0x9F;
    AES_ENCRYPTION_SBOX[111] = 0xA8;
    AES_ENCRYPTION_SBOX[112] = 0x51;
    AES_ENCRYPTION_SBOX[113] = 0xA3;
    AES_ENCRYPTION_SBOX[114] = 0x40;
    AES_ENCRYPTION_SBOX[115] = 0x8F;
    AES_ENCRYPTION_SBOX[116] = 0x92;
    AES_ENCRYPTION_SBOX[117] = 0x9D;
    AES_ENCRYPTION_SBOX[118] = 0x38;
    AES_ENCRYPTION_SBOX[119] = 0xF5;
    AES_ENCRYPTION_SBOX[120] = 0xBC;
    AES_ENCRYPTION_SBOX[121] = 0xB6;
    AES_ENCRYPTION_SBOX[122] = 0xDA;
    AES_ENCRYPTION_SBOX[123] = 0x21;
    AES_ENCRYPTION_SBOX[124] = 0x10;
    AES_ENCRYPTION_SBOX[125] = 0xFF;
    AES_ENCRYPTION_SBOX[126] = 0xF3;
    AES_ENCRYPTION_SBOX[127] = 0xD2;
    AES_ENCRYPTION_SBOX[128] = 0xCD;
    AES_ENCRYPTION_SBOX[129] = 0x0C;
    AES_ENCRYPTION_SBOX[130] = 0x13;
    AES_ENCRYPTION_SBOX[131] = 0xEC;
    AES_ENCRYPTION_SBOX[132] = 0x5F;
    AES_ENCRYPTION_SBOX[133] = 0x97;
    AES_ENCRYPTION_SBOX[134] = 0x44;
    AES_ENCRYPTION_SBOX[135] = 0x17;
    AES_ENCRYPTION_SBOX[136] = 0xC4;
    AES_ENCRYPTION_SBOX[137] = 0xA7;
    AES_ENCRYPTION_SBOX[138] = 0x7E;
    AES_ENCRYPTION_SBOX[139] = 0x3D;
    AES_ENCRYPTION_SBOX[140] = 0x64;
    AES_ENCRYPTION_SBOX[141] = 0x5D;
    AES_ENCRYPTION_SBOX[142] = 0x19;
    AES_ENCRYPTION_SBOX[143] = 0x73;
    AES_ENCRYPTION_SBOX[144] = 0x60;
    AES_ENCRYPTION_SBOX[145] = 0x81;
    AES_ENCRYPTION_SBOX[146] = 0x4F;
    AES_ENCRYPTION_SBOX[147] = 0xDC;
    AES_ENCRYPTION_SBOX[148] = 0x22;
    AES_ENCRYPTION_SBOX[149] = 0x2A;
    AES_ENCRYPTION_SBOX[150] = 0x90;
    AES_ENCRYPTION_SBOX[151] = 0x88;
    AES_ENCRYPTION_SBOX[152] = 0x46;
    AES_ENCRYPTION_SBOX[153] = 0xEE;
    AES_ENCRYPTION_SBOX[154] = 0xB8;
    AES_ENCRYPTION_SBOX[155] = 0x14;
    AES_ENCRYPTION_SBOX[156] = 0xDE;
    AES_ENCRYPTION_SBOX[157] = 0x5E;
    AES_ENCRYPTION_SBOX[158] = 0x0B;
    AES_ENCRYPTION_SBOX[159] = 0xDB;
    AES_ENCRYPTION_SBOX[160] = 0xE0;
    AES_ENCRYPTION_SBOX[161] = 0x32;
    AES_ENCRYPTION_SBOX[162] = 0x3A;
    AES_ENCRYPTION_SBOX[163] = 0x0A;
    AES_ENCRYPTION_SBOX[164] = 0x49;
    AES_ENCRYPTION_SBOX[165] = 0x06;
    AES_ENCRYPTION_SBOX[166] = 0x24;
    AES_ENCRYPTION_SBOX[167] = 0x5C;
    AES_ENCRYPTION_SBOX[168] = 0xC2;
    AES_ENCRYPTION_SBOX[169] = 0xD3;
    AES_ENCRYPTION_SBOX[170] = 0xAC;
    AES_ENCRYPTION_SBOX[171] = 0x62;
    AES_ENCRYPTION_SBOX[172] = 0x91;
    AES_ENCRYPTION_SBOX[173] = 0x95;
    AES_ENCRYPTION_SBOX[174] = 0xE4;
    AES_ENCRYPTION_SBOX[175] = 0x79;
    AES_ENCRYPTION_SBOX[176] = 0xE7;
    AES_ENCRYPTION_SBOX[177] = 0xC8;
    AES_ENCRYPTION_SBOX[178] = 0x37;
    AES_ENCRYPTION_SBOX[179] = 0x6D;
    AES_ENCRYPTION_SBOX[180] = 0x8D;
    AES_ENCRYPTION_SBOX[181] = 0xD5;
    AES_ENCRYPTION_SBOX[182] = 0x4E;
    AES_ENCRYPTION_SBOX[183] = 0xA9;
    AES_ENCRYPTION_SBOX[184] = 0x6C;
    AES_ENCRYPTION_SBOX[185] = 0x56;
    AES_ENCRYPTION_SBOX[186] = 0xF4;
    AES_ENCRYPTION_SBOX[187] = 0xEA;
    AES_ENCRYPTION_SBOX[188] = 0x65;
    AES_ENCRYPTION_SBOX[189] = 0x7A;
    AES_ENCRYPTION_SBOX[190] = 0xAE;
    AES_ENCRYPTION_SBOX[191] = 0x08;
    AES_ENCRYPTION_SBOX[192] = 0xBA;
    AES_ENCRYPTION_SBOX[193] = 0x78;
    AES_ENCRYPTION_SBOX[194] = 0x25;
    AES_ENCRYPTION_SBOX[195] = 0x2E;
    AES_ENCRYPTION_SBOX[196] = 0x1C;
    AES_ENCRYPTION_SBOX[197] = 0xA6;
    AES_ENCRYPTION_SBOX[198] = 0xB4;
    AES_ENCRYPTION_SBOX[199] = 0xC6;
    AES_ENCRYPTION_SBOX[200] = 0xE8;
    AES_ENCRYPTION_SBOX[201] = 0xDD;
    AES_ENCRYPTION_SBOX[202] = 0x74;
    AES_ENCRYPTION_SBOX[203] = 0x1F;
    AES_ENCRYPTION_SBOX[204] = 0x4B;
    AES_ENCRYPTION_SBOX[205] = 0xBD;
    AES_ENCRYPTION_SBOX[206] = 0x8B;
    AES_ENCRYPTION_SBOX[207] = 0x8A;
    AES_ENCRYPTION_SBOX[208] = 0x70;
    AES_ENCRYPTION_SBOX[209] = 0x3E;
    AES_ENCRYPTION_SBOX[210] = 0xB5;
    AES_ENCRYPTION_SBOX[211] = 0x66;
    AES_ENCRYPTION_SBOX[212] = 0x48;
    AES_ENCRYPTION_SBOX[213] = 0x03;
    AES_ENCRYPTION_SBOX[214] = 0xF6;
    AES_ENCRYPTION_SBOX[215] = 0x0E;
    AES_ENCRYPTION_SBOX[216] = 0x61;
    AES_ENCRYPTION_SBOX[217] = 0x35;
    AES_ENCRYPTION_SBOX[218] = 0x57;
    AES_ENCRYPTION_SBOX[219] = 0xB9;
    AES_ENCRYPTION_SBOX[220] = 0x86;
    AES_ENCRYPTION_SBOX[221] = 0xC1;
    AES_ENCRYPTION_SBOX[222] = 0x1D;
    AES_ENCRYPTION_SBOX[223] = 0x9E;
    AES_ENCRYPTION_SBOX[224] = 0xE1;
    AES_ENCRYPTION_SBOX[225] = 0xF8;
    AES_ENCRYPTION_SBOX[226] = 0x98;
    AES_ENCRYPTION_SBOX[227] = 0x11;
    AES_ENCRYPTION_SBOX[228] = 0x69;
    AES_ENCRYPTION_SBOX[229] = 0xD9;
    AES_ENCRYPTION_SBOX[230] = 0x8E;
    AES_ENCRYPTION_SBOX[231] = 0x94;
    AES_ENCRYPTION_SBOX[232] = 0x9B;
    AES_ENCRYPTION_SBOX[233] = 0x1E;
    AES_ENCRYPTION_SBOX[234] = 0x87;
    AES_ENCRYPTION_SBOX[235] = 0xE9;
    AES_ENCRYPTION_SBOX[236] = 0xCE;
    AES_ENCRYPTION_SBOX[237] = 0x55;
    AES_ENCRYPTION_SBOX[238] = 0x28;
    AES_ENCRYPTION_SBOX[239] = 0xDF;
    AES_ENCRYPTION_SBOX[240] = 0x8C;
    AES_ENCRYPTION_SBOX[241] = 0xA1;
    AES_ENCRYPTION_SBOX[242] = 0x89;
    AES_ENCRYPTION_SBOX[243] = 0x0D;
    AES_ENCRYPTION_SBOX[244] = 0xBF;
    AES_ENCRYPTION_SBOX[245] = 0xE6;
    AES_ENCRYPTION_SBOX[246] = 0x42;
    AES_ENCRYPTION_SBOX[247] = 0x68;
    AES_ENCRYPTION_SBOX[248] = 0x41;
    AES_ENCRYPTION_SBOX[249] = 0x99;
    AES_ENCRYPTION_SBOX[250] = 0x2D;
    AES_ENCRYPTION_SBOX[251] = 0x0F;
    AES_ENCRYPTION_SBOX[252] = 0xB0;
    AES_ENCRYPTION_SBOX[253] = 0x54;
    AES_ENCRYPTION_SBOX[254] = 0xBB;
    AES_ENCRYPTION_SBOX[255] = 0x16;

    for( i = 0 ; i < 256 ; i+= 1 ){
     
        a = AES_ENCRYPTION_SBOX[i];
        AES_ENCRYPTION_ISBOX[a] = i;
    }
    for( i = 0 ; i < 128 ; i+= 1 ){
        AES_ENCRYPTION_GM2[i] = i << 1;
    }
    for( ; i < 256 ; i+= 1 ){
        AES_ENCRYPTION_GM2[i] = ((i << 1) & 0xFF) ^ 0x1B;
    }
  
    for( i = 0 ; i < 256 ; i+= 1 ){
      
        a = AES_ENCRYPTION_GM2[i];
        a = AES_ENCRYPTION_GM2[a];
        a = AES_ENCRYPTION_GM2[a];
     
        AES_ENCRYPTION_GM9[i] = a ^ i;
    }
    for( i = 0 ; i < 256 ; i+= 1 ){
      
        a = AES_ENCRYPTION_GM2[i];
    
        AES_ENCRYPTION_GM13[i] = AES_ENCRYPTION_GM2[a] ^ AES_ENCRYPTION_GM9[i];
    }
 
    AES_ENCRYPTION_RCON[0] = 0x8D;
    a = 1;
    for( i = 1 ; i < 30 ; i+= 1 ){
        
        AES_ENCRYPTION_RCON[i] = a;
        a = AES_ENCRYPTION_GM2[a];
    }
}

//--------------------------------------------------------------------------------------------------
// Custom Script: Imperial Bank
//--------------------------------------------------------------------------------------------------

bool ImperialBankLoad(imperial_bank_t &obj, bank source);
bool ImperialBankValid(imperial_bank_t &obj);
void ImperialBankClear(imperial_bank_t &obj);
bool ImperialBankSave(imperial_bank_t &obj);
bool ImperialBankRead(imperial_bank_t &obj, string block, bit_field_t &out);
bool ImperialBankWrite(imperial_bank_t &obj, string block, bit_field_t &in);
// PRIVATE FUNCTIONS
void ImperialBankHeaderKey(imperial_bank_t &obj, imperial_bank_key_t key);
bool ImperialBankReadHeader(imperial_bank_t &obj, bit_field_t &block);
void ImperialBankWriteHeader(imperial_bank_t &obj, bit_field_t &block);
bool ImperialBankReadBlock(imperial_bank_t &obj, string section, string block, imperial_bank_key_t key, bit_field_t &out);
void ImperialBankWriteBlock(imperial_bank_t &obj, string section, string block, imperial_bank_key_t key, bit_field_t &in);
void ImperialBankCryptKey(imperial_bank_key_t key, imperial_bank_key_t key1, imperial_bank_key_t key2, imperial_bank_key_t key3);
void ImperialBankBlockCrypt(imperial_bank_key_t key, bit_field_t &block);
void ImperialBankBlockHash(imperial_bank_key_t outkey, bit_field_t &block);
bool ImperialBankBlockValidate(imperial_bank_key_t key, bit_field_t &block);
// GLOBALS
// ASCII converter.
ascii_channel_t ImperialBankASCIIConverter;
int ImperialBankASCIIConverterRead(){
    return ASCIIChannelRead(ImperialBankASCIIConverter);
}
// IMPLEMENTATION
bool ImperialBankLoad(imperial_bank_t &obj, bank source){///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    string acc;
    int i;
    imperial_bank_key_t key;
    sha1_hasher_t hasher;
    bit_field_t header;
	
    obj.auth = false;
    
/*    if( source == null ){ return false; }
    obj.file = source;
    BankOptionSet(source, c_bankOptionSignature, true);
    if( BankSectionCount(source) != 2 ||
      !BankSectionExists(source, "IBH") ||
      !BankSectionExists(source, "IBD") || 
      BankKeyCount(source, "IBH") != 2 ||
      !BankKeyExists(source, "IBH", "ID") ||
      !BankValueIsType(source, "IBH", "ID", c_bankTypeString) ||
      !BankKeyExists(source, "IBH", "HEAD") ||
      !BankValueIsType(source, "IBH", "HEAD", c_bankTypeString) ){ return false; }
 */
	obj.owners = ibhid_s;//BankValueGetAsString(source, "IBH", "ID");
    acc = ibhid_s;//PlayerHandle(BankPlayer(source));
	if( acc=="" ){ acc = "SC2E-TEST-ACCOUNT"; }
 
    ASCIIChannelSetup(ImperialBankASCIIConverter, obj.owners);
    SHA1HasherHashData(hasher, ImperialBankASCIIConverterRead, ASCIIChannelLength(ImperialBankASCIIConverter));
    SHA1HasherHash(hasher, obj.key);
   
    ImperialBankHeaderKey(obj, key);
  
    if( !ImperialBankReadBlock(obj, "IBH", "HEAD", key, header) ||
      !ImperialBankReadHeader(obj, header) ){ return false; }
 
    if( obj.owners.substr(obj.accounts[obj.loadowner].pos-1, obj.accounts[obj.loadowner].pos + obj.accounts[obj.loadowner].len - 1) == acc ){
        obj.auth = true;//BankVerify(source);
    }
    else{
        for( i = 0 ; i < obj.accountn ; i+= 1 ){
            if( obj.owners.substr(obj.accounts[i].pos-1, obj.accounts[i].pos + obj.accounts[i].len - 1) == acc ){
                obj.loadowner = i;
                obj.auth = true;
                break;
            }
        }
    }
  
    return true;
}
bool ImperialBankValid(imperial_bank_t &obj){
    return obj.auth;
}
void ImperialBankClear(imperial_bank_t &obj){
    sha1_hasher_t hasher;
   
/*    while( BankSectionCount(obj.file) > 0 ){
        BankSectionRemove(obj.file, BankSectionName(obj.file, 0));
    }
    BankOptionSet(obj.file, c_bankOptionSignature, true);
 
    BankSectionCreate(obj.file, "IBD");
    BankSectionCreate(obj.file, "IBH");
*/ 
    obj.owners = ibhid_s;//PlayerHandle(BankPlayer(obj.file));
    
	if( obj.owners=="" ){ obj.owners = "SC2E-TEST-ACCOUNT"; }
//    BankValueSetFromString(obj.file, "IBH", "ID", obj.owners);
    obj.accountn = 1;
    obj.accounts[0].pos = 1;
    obj.accounts[0].len = obj.owners.length();
    obj.loadowner = 0;
    
    ASCIIChannelSetup(ImperialBankASCIIConverter, obj.owners);
    SHA1HasherHashData(hasher, ImperialBankASCIIConverterRead, ASCIIChannelLength(ImperialBankASCIIConverter));
    SHA1HasherHash(hasher, obj.key);
   
    obj.savenum = 0;
    obj.blocknum = 0;
    obj.auth = true;
}
bool ImperialBankSave(imperial_bank_t &obj){
    imperial_bank_key_t key;
    bit_field_t header;
   BitFieldInitialize(header,0,false);
    if( !obj.auth ){ return false; }
   
    obj.savenum = (obj.savenum + 1) % (1 << 18);
   
    ImperialBankWriteHeader(obj, header);
   
    ImperialBankHeaderKey(obj, key);///////////////////////////////////////////////////////////////////////////////////////////FIXME
    
    ImperialBankWriteBlock(obj, "IBH", "HEAD", key, header);
   
//    BankSave(obj.file);
    return true;
}
bool ImperialBankRead(imperial_bank_t &obj, string block, bit_field_t &out){
    sha1_hasher_t hasher;
    imperial_bank_key_t key;
  
    if( !obj.auth ){ return false; }
 
    ASCIIChannelSetup(ImperialBankASCIIConverter, block);
    SHA1HasherHashData(hasher, ImperialBankASCIIConverterRead, ASCIIChannelLength(ImperialBankASCIIConverter));
    SHA1HasherHash(hasher, key);
   
    return ImperialBankReadBlock(obj, "IBD", block, key, out);
}
bool ImperialBankWrite(imperial_bank_t &obj, string block, bit_field_t &in){
    sha1_hasher_t hasher;
    imperial_bank_key_t key;
    
    if( !obj.auth ){ return false; }
  
    //if( !BankKeyExists(obj.file, "IBD", block) ){
    //    obj.blocknum+= 1;
    //}
    ASCIIChannelSetup(ImperialBankASCIIConverter, block);
    SHA1HasherHashData(hasher, ImperialBankASCIIConverterRead, ASCIIChannelLength(ImperialBankASCIIConverter));
    SHA1HasherHash(hasher, key);
   
    ImperialBankWriteBlock(obj, "IBD", block, key, in);
    return true;
}
void ImperialBankHeaderKey(imperial_bank_t &obj, imperial_bank_key_t key){
  
    key[0] = 0x12345678 ^ obj.key[3];
    key[1] = obj.key[0] ^ obj.key[4] ^ 0x7A8B9CAD;
    key[2] = 0x31415926;
    key[3] = obj.key[1] ^ obj.key[2] ^ 0x42184218;
    key[4] = 0x27182818;
}
bool ImperialBankReadHeader(imperial_bank_t &obj, bit_field_t &block){
    int i = 0;
    int temp = 0;
   
    BitFieldSeek(block, 0);
    
    i = BitFieldGetSize(block);
    if( i < 42 ){ return false; }
    i-= 24;
  
    if( BitFieldRead(block, 6) > 0 ){ return false; }
    
    obj.savenum = BitFieldRead(block, 18);
    obj.blocknum = BitFieldRead(block, 10);
    obj.loadowner = BitFieldRead(block, 4);
    obj.accountn = BitFieldRead(block, 4);
  
    if( i < (obj.accountn * 17) ){ return false; }
    for( i = 0 ; i < obj.accountn ; i+= 1 ){
        obj.accounts[i].pos = BitFieldRead(block, 10);
        obj.accounts[i].len = BitFieldRead(block, 7);
    }
    
    //if( BankKeyCount(obj.file, "IBD") != obj.blocknum ||
    //  obj.loadowner >= obj.accountn ){ return false; }
   
    temp = 1;
    for( i = 0 ; i < obj.accountn ; i+= 1 ){
        if( obj.accounts[i].pos != temp ||
          obj.accounts[i].len == 0 ){ return false; }
        temp+= obj.accounts[i].len;
    }
    if( (temp - 1) != obj.owners.length() ){ return false; }
    
    return true;
}

void ImperialBankWriteHeader(imperial_bank_t &obj, bit_field_t &block){
    int i = 0;
   
    BitFieldInitialize(block, 42 + (obj.accountn * 17), false);
    
    BitFieldWrite(block, 0, 6);
    
    BitFieldWrite(block, obj.savenum, 18);
    BitFieldWrite(block, obj.blocknum, 10);
    BitFieldWrite(block, obj.loadowner, 4);
    BitFieldWrite(block, obj.accountn, 4);
    
    for( i = 0 ; i < obj.accountn ; i+= 1 ){
        BitFieldWrite(block, obj.accounts[i].pos, 10);
        BitFieldWrite(block, obj.accounts[i].len, 7);
    }
}

bool ImperialBankReadBlock(imperial_bank_t &obj, string section, string block, imperial_bank_key_t key, bit_field_t &out){
    imperial_bank_key_t ekey;
    imperial_bank_key_t hkey;
    string s;
    int i;
    int end;
   
  /*  if( !BankKeyExists(obj.file, section, block) ){ return false; }
    
    else if( !BankValueIsType(obj.file, section, block, c_bankTypeString) ){
        BankKeyRemove(obj.file, section, block);
        obj.blocknum-= 1;
        return false;
    }*/
    //s = BankValueGetAsString(obj.file, section, block);//header
	if(section=="IBD"){
		s=ibduac_s;
	}
	else if(block=="HEAD"){
		s=head_s;
	}
	else{
		s=ibhid_s;
	}
    end = s.length();
  
    if( (end * 6) > (BIT_FIELD_SIZE * 32 + 160) ||
      ((end * 6 - 160) % 128) >= 6 )
	{ return false; }
    
    BitFieldSetSize(out, 162);
    BitFieldSeek(out, 0);
    for( i = 1 ; i <= 27 ; i+= 1 ){
        BitFieldWrite(out, ASCIIUtilBase64ToInt(s, i), 6);
    }
    for( i = 0 ; i < 5 ; i+= 1 ){
        hkey[i] = BitFieldGet(out, i);
    }
  
    BitFieldSet(out, BitFieldGet(out, 5), 0);
    BitFieldSeek(out, 2);
    BitFieldSetSize(out, (((end * 6) - 160) / 128) * 128);
   
    for( i = 28 ; i < end ; i+= 1 ){
        BitFieldWrite(out, ASCIIUtilBase64ToInt(s, i), 6);
    }
   
    BitFieldWrite(out, ASCIIUtilBase64ToInt(s, end), BitFieldRemaining(out));
    
    ImperialBankCryptKey(ekey, obj.key, key, hkey);//算法
    ImperialBankBlockCrypt(ekey, out);
  
    return ImperialBankBlockValidate(hkey, out);
}
void ImperialBankWriteBlock(imperial_bank_t &obj, string section, string block, imperial_bank_key_t key, bit_field_t &in){
    imperial_bank_key_t ekey;
    imperial_bank_key_t hkey;
    string s;
    string h;
    int i;
    int end;
 
    BitFieldResize(in, ((BitFieldGetSize(in) + 127) & ((-1) << 7)));
 
    ImperialBankBlockHash(hkey, in);
   
    ImperialBankCryptKey(ekey, obj.key, key, hkey);
    ImperialBankBlockCrypt(ekey, in);
  
    s = "";
    BitFieldSeek(in, 2);
    end = BitFieldRemaining(in) / 6;
    for( i = 0 ; i < end ; i+= 1 ){
        s+= ASCIIUtilIntToBase64(BitFieldRead(in, 6));
    }
    
    end = BitFieldRemaining(in);
    if( end > 0 ){ 
        s+= ASCIIUtilIntToBase64(BitFieldRead(in, end) | ((hkey[2] << end) & 0x3F));
    }
   
    BitFieldSetSize(in, 162);
    BitFieldSeek(in, 0);
 
    BitFieldSet(in, BitFieldGet(in, 0), 5);
   
    for( i = 0 ; i < 5 ; i+= 1 ){
        BitFieldSet(in, hkey[i], i);
    }
    
    h = "";
    for( i = 0 ; i < 27 ; i+= 1 ){
        h+= ASCIIUtilIntToBase64(BitFieldRead(in, 6));
    }
    
    //BankValueSetFromString(obj.file, section, block, h + s);

	cout<<block<<endl;
	cout<<(h+s)<<endl;
	if(block=="UAC"){
		makeibduac=h+s;
	}
	else if (block=="HEAD"){
		makeibhhead=h+s;
	}

}
void ImperialBankCryptKey(imperial_bank_key_t key, imperial_bank_key_t key1, imperial_bank_key_t key2, imperial_bank_key_t key3){
 
    key[0] = key1[1] ^ key2[2] ^ ((key3[3] << 13) | ((key3[3] >> 19) & 0x1FFF));
    key[1] = key1[3] ^ key2[0] ^ key3[0];
    key[2] = key1[0] ^ key2[3] ^ key3[2];
    key[3] = key1[2] ^ key2[1] ^ key3[4];
    key[4] = key1[4] ^ key2[4] ^ key3[1];
}
void ImperialBankBlockCrypt(imperial_bank_key_t key, bit_field_t &block){
    aes_encryption_t crypt;
    aes_encryption_block_t eblock;
    int i;
    int end;
    int ckey;
    
    ckey = key[0] ^ key[1] ^ key[2] ^ key[3] ^ key[4];
    AESEncryptionSetup(crypt, key);
   
    end = BitFieldGetSize(block) / 32;
    i = 0;
    while( i < end ){
       
        eblock[0] = i;
        eblock[1] = ~i;
        eblock[2] = i ^ ckey;
        eblock[3] = (-i) ^ ckey;
        AESEncryptionCipher(crypt, eblock);
   
        BitFieldSet(block, BitFieldGet(block, i) ^ eblock[1], i);
        i+= 1;
        BitFieldSet(block, BitFieldGet(block, i) ^ eblock[2], i);
        i+= 1;
        BitFieldSet(block, BitFieldGet(block, i) ^ eblock[3], i);
        i+= 1;
        BitFieldSet(block, BitFieldGet(block, i) ^ eblock[0], i);
        i+= 1;
    }
}
void ImperialBankBlockHash(imperial_bank_key_t outkey, bit_field_t &block){
    sha1_hasher_t hasher;
    sha1_hasher_block_t hashblock;
    int i=0;
    int end=0;
    int j=0;
    int eob=0;
	for(j=0;j<16;j++){
		hashblock[j]=0;
	}
    SHA1HasherInitalize(hasher);
    end = BitFieldGetSize(block) / 32;
  
    while( i < end ){
      
        eob = end - i;
        if( eob > 16 ){ eob = 16; }
      
        for( j = 0 ; j < eob ; j+= 1 ){
            hashblock[j] = BitFieldGet(block, i);
            i+= 1;
        }
       
        SHA1HasherProcess(hasher, hashblock);
    }
    SHA1HasherProcessFinal(hasher, hashblock, end * 4);
    SHA1HasherHash(hasher, outkey);
}
bool ImperialBankBlockValidate(imperial_bank_key_t key, bit_field_t &block){
    imperial_bank_key_t hash;
    int i;
    bool result;
    ImperialBankBlockHash(hash, block);
   
    result = true;
    for( i = 0 ; i < 5 ; i+= 1 ){
        result = result && (key[i] == hash[i]);
    }
    return result;
}




//--------------------------------------------------------------------------------------------------
// Custom Script: Player Bank
//--------------------------------------------------------------------------------------------------
// ASCII converter.

int gv_rankMax[4];
int gv_playerRankSet[13];
const int gv_decals = 52;
const int gv_camos = 52;
const int gv_sIcount = 70;
const int gv_achievementCount = 50;
int gv_rankXPMin[4][18];
string gv_rankActorMsg[4][18];
string gv_rankDecal[4][18];
int gv_playerExperience[4][13];
int gv_playerStartingXP[13];
int gv_playerRevives[13];
int gv_playerRevivesGame[13];
int gv_playerGamesPlayed[13];
int gv_playerAvgGameTime[13];
bool gv_gamesPlayer1;
int gv_playerkills[13];
int gv_playermassivekills[13];
int gv_playerheals[13];
int gv_gamesWon[13][13];
int gv_playerhits[13];
int gv_playerImportedFromUA3[17];
int gv_funcdialogoffsets[3][13];
bool gv_playercamounlocked[gv_camos + 1][13];
bool gv_playerdecalunlocked[gv_decals + 1][13];
bool gv_sIunlocked[gv_sIcount + 1][13];
bool gv_achievementUnlocked[gv_achievementCount + 1][13];

ascii_channel_t PlayerBankImportConverter;
int PlayerBankImportConverterRead(){
    return ASCIIChannelRead(PlayerBankImportConverter);
}
string PlayerBankImportConverterSignature(string s){
    sha1_hasher_t hasher;
    imperial_bank_key_t hash;
   
    ASCIIChannelSetup(PlayerBankImportConverter, s);
    SHA1HasherHashData(hasher, PlayerBankImportConverterRead, ASCIIChannelLength(PlayerBankImportConverter));
    SHA1HasherHash(hasher, hash);
    return ASCIIUtilIntToHex(hash[0]) + ASCIIUtilIntToHex(hash[1]) + ASCIIUtilIntToHex(hash[2]) + ASCIIUtilIntToHex(hash[3]) + ASCIIUtilIntToHex(hash[4]);
}
imperial_bank_t PlayerBanks[16];
void PlayerBankNew(int player){
    ImperialBankClear(PlayerBanks[player]);
}
bool PlayerBankLoad(int player){
    bit_field_t block;
    int i;
    int ver;
    int len;
    
    if( !ImperialBankLoad(PlayerBanks[player], 1))//gv_banks[player]) )
	{ return false; }
    
    BitFieldInitialize(block, 32, false);
   
    if( !ImperialBankRead(PlayerBanks[player], "UAC", block) ){ return false; }
    BitFieldSeek(block, 0);
  
    len = BitFieldGetSize(block);
    
    ver = BitFieldRead(block, 9);
    
    if( ver > 2 ){ return false; }
  
    if( len != 640 ){ return false; }
  
    gv_playerImportedFromUA3[player] = BitFieldRead(block, 2);
   
    for( i = 1 ; i <= 3 ; i+= 1 ){
        gv_playerExperience[i][player] = BitFieldRead(block, 20);
		printf("exp %d \n", gv_playerExperience[i][player]);
    }
    gv_playerStartingXP[player] = gv_playerExperience[1][player]; // ???
  
    gv_playerGamesPlayed[player] = BitFieldRead(block, 16);
    gv_playerRevives[player] = BitFieldRead(block, 20);
    gv_playerAvgGameTime[player] = BitFieldRead(block, 16);
    
    gv_funcdialogoffsets[1][player] = BitFieldRead(block, 12) - 2048;
    gv_funcdialogoffsets[2][player] = BitFieldRead(block, 12) - 2048;
	printf("gamesplayed %d \n", gv_playerGamesPlayed[player]);
	printf("revives %d \n", gv_playerRevives[player]);
	printf("avggametime %d \n", gv_playerAvgGameTime[player]);
	printf("funcdialog1 %d \n", gv_funcdialogoffsets[1][player]);
	printf("funcdialog2 %d \n", gv_funcdialogoffsets[2][player]);
  
    if( ver == 0 ){
        
        for( i = 2 ; i <= 44 ; i+= 1 ){
            gv_playercamounlocked[i][player] = BitFieldRead(block, 1) != 0;
        }
        for( ; i <= gv_camos ; i+= 1 ){
            gv_playercamounlocked[i][player] = false; 
        }
    }else{
        
        for( i = 2 ; i <= gv_camos ; i+= 1 ){
            gv_playercamounlocked[i][player] = BitFieldRead(block, 1) != 0;
        }
    }   
	cout<<"camos"<<endl;
	for( i = 2 ; i <= gv_camos ; i+= 1 ){
		
            cout<<gv_playercamounlocked[i][player];
    }
	cout<<endl;

    if( ver == 0 ){
        
        for( i = 1 ; i <= 29 ; i+= 1 ){
            gv_playerdecalunlocked[i][player] = BitFieldRead(block, 1) != 0;
        }
        for( ; i <= gv_decals ; i+= 1 ){
            gv_playerdecalunlocked[i][player] = false; 
        }
  
    }else{
       for( i = 1 ; i <= 35 ; i+= 1 ){
            gv_playerdecalunlocked[i][player] = BitFieldRead(block, 1) != 0;
        }
    }   


    if ( ver == 0 ){
	
    	for( i = 1 ; i <= 64 ; i+= 1 ){
            gv_sIunlocked[i][player] = BitFieldRead(block, 1) != 0;
    }
        for ( ; i <=gv_sIcount ; i+= 1 ){
              gv_sIunlocked[i][player] = false; 
        }
    }else{
        
        for( i = 1 ; i <= gv_sIcount ; i+= 1 ){
            gv_sIunlocked[i][player] = BitFieldRead(block, 1) != 0;
        }
    }
cout<<"si"<<endl;
  for( i = 1 ; i <= gv_sIcount ; i+= 1 ){
			
           cout<<gv_sIunlocked[i][player];
     }
  cout<<endl;
      if ( ver == 0 ){
	
    	for( i = 1 ; i <= 3 ; i+= 1 ){
            gv_achievementUnlocked[i][player] = BitFieldRead(block, 1) != 0;
    }
        for ( ; i <=gv_achievementCount ; i+= 1 ){
              gv_achievementUnlocked[i][player] = false; 
        }
    }else{
        
        for( i = 1 ; i <= gv_achievementCount ; i+= 1 ){
            gv_achievementUnlocked[i][player] = BitFieldRead(block, 1) != 0;
        }
    }

cout<<"achieve"<<endl;
 for( i = 1 ; i <= gv_achievementCount ; i+= 1 ){
			
            cout<<gv_achievementUnlocked[i][player];
        }
 cout<<endl;
cout<<"gamewon"<<endl;
    for( i = 1 ; i <= 12 ; i+= 1 ){
        gv_gamesWon[i][player] = BitFieldRead(block, 16);
		
		cout<<gv_gamesWon[i][player]<<" ";
    }
	cout<<endl;
    if( ver == 2 ){
        
        for( i = 36 ; i <= gv_decals ; i+= 1 ){
        gv_playerdecalunlocked[i][player] = BitFieldRead(block, 1) != 0;
        
        }
    }

	cout<<"decal"<<ver<<endl;
	for( i = 1 ; i <= gv_decals ; i+= 1 ){
		
            cout<<gv_playerdecalunlocked[i][player];
    }
	cout<<endl;
    return true;
}
int PlayerBankClampInt(int in, int len){
    int max;
    if( in < 0 ){ return 0; }
    max = (~((-1) << len));
    if( in > max ){ return max; }
    return in;
}

void PlayerBankWriteBool(bit_field_t &block, bool val){
    if( val ){ BitFieldWrite(block, 1, 1); }
    else{ BitFieldWrite(block, 0, 1); }
}

bool PlayerBankSave(int player){
    bit_field_t block;
    int i;
    if( !ImperialBankValid(PlayerBanks[player]) ){
        ImperialBankClear(PlayerBanks[player]);
    }
   
    BitFieldInitialize(block, 640, false);
    BitFieldSeek(block, 0);
   
    BitFieldWrite(block, 2, 9);
    
    BitFieldWrite(block, gv_playerImportedFromUA3[player], 2);
  
    for( i = 1 ; i <= 3 ; i+= 1 ){
        BitFieldWrite(block, PlayerBankClampInt(gv_playerExperience[i][player], 20), 20);
    }
    
    BitFieldWrite(block, PlayerBankClampInt(gv_playerGamesPlayed[player], 16), 16);
    BitFieldWrite(block, PlayerBankClampInt(gv_playerRevives[player], 20), 20);
    BitFieldWrite(block, PlayerBankClampInt(gv_playerAvgGameTime[player], 16), 16);
    BitFieldWrite(block, PlayerBankClampInt(gv_funcdialogoffsets[1][player] + 2048, 12), 12);
    BitFieldWrite(block, PlayerBankClampInt(gv_funcdialogoffsets[2][player] + 2048, 12), 12);
  
    for( i = 2 ; i <= gv_camos ; i+= 1 ){
        PlayerBankWriteBool(block, gv_playercamounlocked[i][player]);
    }
   
    for( i = 1 ; i <= 35 ; i+= 1 ){
        PlayerBankWriteBool(block, gv_playerdecalunlocked[i][player]);
    }
   
    for( i = 1 ; i <= gv_sIcount ; i+= 1 ){
        PlayerBankWriteBool(block, gv_sIunlocked[i][player]);
    }
    for( i = 1 ; i <= gv_achievementCount ; i+= 1 ){
        PlayerBankWriteBool(block, gv_achievementUnlocked[i][player]);
    }
    
    for( i = 1 ; i <= 12 ; i+= 1 ){
        BitFieldWrite(block, PlayerBankClampInt(gv_gamesWon[i][player], 16), 16);
    }
    
    for( i = 36 ; i <= gv_decals ; i+= 1 ){
        PlayerBankWriteBool(block, gv_playerdecalunlocked[i][player]);
    }
  
    if( !ImperialBankWrite(PlayerBanks[player], "UAC", block) ){ return false; }
    return ImperialBankSave(PlayerBanks[player]);
}






bool PlayerBankMake(int player){
    bit_field_t block;
    int i;

        ImperialBankClear(PlayerBanks[player]);

   
    BitFieldInitialize(block, 640, false);
    BitFieldSeek(block, 0);
   
    BitFieldWrite(block, 2, 9);
    
    BitFieldWrite(block, gv_playerImportedFromUA3[player], 2);
  
    for( i = 1 ; i <= 3 ; i+= 1 ){
        BitFieldWrite(block, PlayerBankClampInt(gv_playerExperience[i][player], 20), 20);
    }
    
    BitFieldWrite(block, PlayerBankClampInt(gv_playerGamesPlayed[player], 16), 16);
    BitFieldWrite(block, PlayerBankClampInt(gv_playerRevives[player], 20), 20);
    BitFieldWrite(block, PlayerBankClampInt(gv_playerAvgGameTime[player], 16), 16);
    BitFieldWrite(block, PlayerBankClampInt(gv_funcdialogoffsets[1][player] + 2048, 12), 12);
    BitFieldWrite(block, PlayerBankClampInt(gv_funcdialogoffsets[2][player] + 2048, 12), 12);
  
    for( i = 2 ; i <= gv_camos ; i+= 1 ){
        PlayerBankWriteBool(block, gv_playercamounlocked[i][player]);
    }
   
    for( i = 1 ; i <= 35 ; i+= 1 ){
        PlayerBankWriteBool(block, gv_playerdecalunlocked[i][player]);
    }
   
    for( i = 1 ; i <= gv_sIcount ; i+= 1 ){
        PlayerBankWriteBool(block, gv_sIunlocked[i][player]);
    }
    for( i = 1 ; i <= gv_achievementCount ; i+= 1 ){
        PlayerBankWriteBool(block, gv_achievementUnlocked[i][player]);
    }
    
    for( i = 1 ; i <= 12 ; i+= 1 ){
        BitFieldWrite(block, PlayerBankClampInt(gv_gamesWon[i][player], 16), 16);
    }
    
    for( i = 36 ; i <= gv_decals ; i+= 1 ){
        PlayerBankWriteBool(block, gv_playerdecalunlocked[i][player]);
    }
  
    if( !ImperialBankWrite(PlayerBanks[player], "UAC", block) ){ return false; }
    return ImperialBankSave(PlayerBanks[player]);
}















//--------------------------------------------------------------------------------------------------
// Custom Script Initialization
//--------------------------------------------------------------------------------------------------
void InitCustomScript () {
    ASCIIUtilInit();
    AESEncryptionInit();
}



void GetProgramDir()     
{      
    char exeFullPath[MAX_PATH]; // Full path   
    string strPath = "";   
	//GetCurrentDirectory(MAX_PATH,exeFullPath);
    GetModuleFileNameA(NULL,exeFullPath,MAX_PATH);   
    strPath=(string)exeFullPath;    // Get full path of the file   
  
    int pos = strPath.find_last_of('\\', strPath.length());   
	strPath=strPath.substr(0, pos);
	ShellExecuteA(NULL,"open",strPath.c_str(),NULL,NULL,SW_SHOW);
    //return strPath.substr(0, pos);  // Return the directory without the file name   
}      
  









int _tmain(int argc, _TCHAR* argv[])
{
	InitCustomScript();
	string lv_string="";
	char choice;
	char input[100];
	int i;
	int inputnum=0;
	ofstream makefile;
	

	while(1){
		choice=0;
		for(i=0;i<100;i++){
			input[i]=false;
		}

		cout<<"select mode: 1=read 2=make 3=exit"<<endl;
		cin>>choice;
	
		fflush(stdin);
		if(choice=='1'){
			cout<<"ibduac"<<endl;
			gets_s(ibduac);
			ibduac_s=ibduac;
			fflush(stdin);
			cout<<"ibhid"<<endl;
			gets_s(ibhid);
			ibhid_s=ibhid;
			fflush(stdin);
			cout<<"head"<<endl;
				gets_s(head);
			head_s=head;
			fflush(stdin);
			PlayerBankLoad(1);
		}
		else if(choice=='2'){
			cout<<"ibhid"<<endl;
			gets_s(ibhid);
			ibhid_s=ibhid;
			fflush(stdin);
			cout<<"exp1"<<endl;
			cin>>gv_playerExperience[1][1];
			fflush(stdin);
			cout<<"exp2"<<endl;
			cin>>gv_playerExperience[2][1];
			fflush(stdin);
			cout<<"exp3"<<endl;
			cin>>gv_playerExperience[3][1];
			fflush(stdin);
			cout<<"gameplayed"<<endl;
			cin>>gv_playerGamesPlayed[1];
			fflush(stdin);
			cout<<"revives"<<endl;
			cin>>gv_playerRevives[1];
			fflush(stdin);
			cout<<"playerAvgGameTime"<<endl;
			cin>>gv_playerAvgGameTime[1];
			fflush(stdin);
			cout<<"dialog1 350"<<endl;
			gv_funcdialogoffsets[1][1]=350;
			//cin>>gv_funcdialogoffsets[1][1];
			cout<<"dialog2 -5"<<endl;
			gv_funcdialogoffsets[2][1]=-5;
			//cin>>gv_funcdialogoffsets[2][1];
			////////////////////////////////////////////////////////////////
			for(i=0;i<100;i++){
			input[i]=false;
			}
			choice=0;
			cout<<" camos 1:lock 2:unlock 3:custom"<<endl;
			cin>>choice;
			fflush(stdin);
			if(choice=='1'){
				for( i = 2 ; i <= gv_camos ; i+= 1 ){
					gv_playercamounlocked[i][1]=false;
				}		
			}	else if(choice=='2'){
				for( i = 2 ; i <= gv_camos ; i+= 1 ){
					gv_playercamounlocked[i][1]=true;
				}		
			}	else{
				cout<<" camos x51"<<endl;
				gets_s(input);
				fflush(stdin);
				for( i = 2 ; i <= gv_camos ; i+= 1 ){
					gv_playercamounlocked[i][1]=(input[i-2]>'0');
				}		
			}
			//////////////////////////////////////////////////////////////////////
			for(i=0;i<100;i++){
			input[i]=false;
			}
			choice=0;
			cout<<" si 1:lock 2:unlock 3:custom"<<endl;
			cin>>choice;
			fflush(stdin);
			if(choice=='1'){
				for( i = 1 ; i <= gv_sIcount ; i+= 1 ){
					gv_sIunlocked[i][1]=false;
				}		
			}	else if(choice=='2'){
				for( i = 1 ; i <= gv_sIcount ; i+= 1 ){
					gv_sIunlocked[i][1]=true;
				}		
			}	else{
				cout<<" si x70"<<endl;
				gets_s(input);
				fflush(stdin);
				for( i = 1 ; i <= gv_sIcount ; i+= 1 ){
					gv_sIunlocked[i][1]=(input[i-1]>'0');
				}		
			}

			//////////////////////////////////////////////////////////////////////////////
			for(i=0;i<100;i++){
			input[i]=false;
			}
			choice=0;
			cout<<" achieve 1:lock 2:unlock 3:custom"<<endl;
			cin>>choice;
			fflush(stdin);
			if(choice=='1'){
				for( i = 1 ; i <= gv_achievementCount ; i+= 1 ){
					gv_achievementUnlocked[i][1]=false;
				}		
			}	else if(choice=='2'){
				for( i = 1 ; i <= gv_achievementCount ; i+= 1 ){
					gv_achievementUnlocked[i][1]=true;
				}		
			}	else{
				cout<<" achieve x50"<<endl;
				gets_s(input);
				fflush(stdin);
				for( i = 1 ; i <= gv_achievementCount ; i+= 1 ){
					gv_achievementUnlocked[i][1]=(input[i-1]>'0');
				}		
			}

			//////////////////////////////////////////////////////////////////////////////////
			for(i=0;i<100;i++){
			input[i]=false;
			}
			choice=0;
			cout<<" win 1:all0 2:all1 3:custom"<<endl;
			cin>>choice;
			fflush(stdin);
			if(choice=='1'){
				for( i = 1 ; i <= 12 ; i+= 1 ){
					gv_gamesWon[i][1]=0;
				}		
			}	else if(choice=='2'){
				for( i = 1 ; i <= 12 ; i+= 1 ){
					gv_gamesWon[i][1]=1;
				}		
			}	else{
				cout<<" win x12"<<endl;
				for( i = 1 ; i <= 12 ; i+= 1 ){
					cout<<" win "<<i<<endl;
					cin>>gv_gamesWon[i][1];
					fflush(stdin);
				}		
			}

			//////////////////////////////////////////////////////////////////////////
			for(i=0;i<100;i++){
			input[i]=false;
			}
			choice=0;
			cout<<" decal 1:lock 2:unlock 3:custom"<<endl;
			cin>>choice;
			fflush(stdin);
			if(choice=='1'){
				for( i = 1 ; i <= gv_decals ; i+= 1 ){
					gv_playerdecalunlocked[i][1]=false;
				}		
			}	else if(choice=='2'){
				for( i = 1 ; i <= gv_decals ; i+= 1 ){
					gv_playerdecalunlocked[i][1]=true;
				}		
			}	else{
				cout<<" decal x52"<<endl;
				gets_s(input);
				fflush(stdin);
				for( i = 1 ; i <= gv_decals ; i+= 1 ){
					gv_playerdecalunlocked[i][1]=(input[i-1]>'0');
				}
			}



			PlayerBankMake(1);
			makefile.open("UAC.SC2Bank");
			makefile<<"<?xml version=\"1.0\" encoding=\"utf-8\"?>"<<"\n";
			makefile<<"<Bank version=\"1\">"<<"\n";
			makefile<<"    <Section name=\"IBD\">"<<"\n";
			makefile<<"        <Key name=\"UAC\">"<<"\n";
			makefile<<"            <Value string=\""<<makeibduac<<"\"/>"<<"\n";
			makefile<<"        </Key>"<<"\n";
			makefile<<"    </Section>"<<"\n";
			makefile<<"    <Section name=\"IBH\">"<<"\n";
			makefile<<"        <Key name=\"ID\">"<<"\n";
			makefile<<"            <Value string=\""<<ibhid_s<<"\"/>"<<"\n";
			makefile<<"        </Key>"<<"\n";
			makefile<<"        <Key name=\"HEAD\">"<<"\n";
			makefile<<"            <Value string=\""<<makeibhhead<<"\"/>"<<"\n";
			makefile<<"        </Key>"<<"\n";
			makefile<<"    </Section>"<<"\n";
			makefile<<"    <Signature value=\" \"/>"<<"\n";
			makefile<<"</Bank>"<<"\n";
			makefile<<"\n";
			makefile.close();
			makefile.clear();
			GetProgramDir() ;
		}
		else{
			break;
		}
	}

	//PlayerBankSave(1);
	//getchar();
	
	_getch();
	return 0;
}

