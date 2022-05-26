//Bob's code
//Group5
//Yasaswini Gorantla
//Roopa Sri Singam
#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include <iterator>
#include <fstream>
#include <tomcrypt.h>
#include <iomanip>
#include <bits/stdc++.h>
#include <regex>
using namespace std;
//---------------------------------------------------------------------------
//=====================AES Decryption in CTR mode=========================================
unsigned char* AESctr_decrypt(unsigned char *buffer, unsigned char *key)
{
    unsigned char IV[32] = "abcdefghijklmnopqrstuvwxyzabcde";
    symmetric_CTR ctr;
    //int x;
    //cout<<"inside the decrypt"<<endl;
		register_cipher(&aes_desc);
	//cout<<buffer<<endl;
    ctr_start(
             find_cipher("aes"),    /* index of desired cipher */
             IV,                        /* the initial vector */
             key,                       /* the secret key */
             32,                        /* length of secret key (16 bytes) */
             0,                         /* 0 == default # of rounds */
             CTR_COUNTER_LITTLE_ENDIAN, /* Little endian counter */
             &ctr);
		ctr_setiv(IV,
              32,
              &ctr);
		ctr_decrypt( buffer, /* ciphertext */
							buffer, /* plaintext */
								1024, /* length of plaintext */
								&ctr); /* CTR state */
  	ctr_done(&ctr);

		//cout<<buffer<<endl;
		//zeromem(key, sizeof(key));
		
    zeromem(&ctr, sizeof(ctr));
    return buffer;
}

//===================SHA256 Function=========================================
unsigned char* hashSHA2(unsigned char* input)
{
	unsigned char* hash_res = new unsigned char[sha256_desc.hashsize];
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, (const unsigned char*) input, 32);
    sha256_done(&md, hash_res);
    return hash_res;
}

//====================HMAC_Computation==========================================
void HMAC_Computation(char *message, unsigned char *mac, unsigned char *key)
{
    int idx;
    hmac_state hmac;
    unsigned char dst[MAXBLOCKSIZE];
    unsigned long dstlen;
    register_hash(&sha256_desc);
    idx = find_hash("sha256");
    hmac_init(&hmac, idx, key, 32);
    hmac_process(&hmac, (const unsigned char*) message, sizeof(message));
    dstlen = sizeof(dst);
    
    hmac_done(&hmac, dst, &dstlen);
    memcpy(mac, dst, dstlen);
}


int main () {

// Prepare our context and socket
	zmq::context_t context (2);
	zmq::socket_t socket (context, zmq::socket_type::rep);
	socket.bind ("tcp://*:5555");
	zmq::message_t request;

	// Wait for next request from client
	//receive ciphertext
	socket.recv (request, zmq::recv_flags::none);
	string rpl = string(static_cast<char*>(request.data()), request.size());
	string cipherhex=rpl;
	
	zmq::message_t request2;
	socket.recv (request2, zmq::recv_flags::none);
	string rpl2 = string(static_cast<char*>(request2.data()), request2.size());
	string aliceAggregate=rpl2;

	
	
	//Read Key from InitialKey.txt" 
	string key;
	string key1;
    	fstream filename;
    	filename.open("InitialKey.txt",ios::in);
    	if(filename.is_open()){
    	string x;
    	while(getline(filename,x)){
    	key+=x;
    	key1+=x;
    	}
    	filename.close();
    	}
 
	
	istringstream ch(cipherhex);
	string ciphertext="";
	unsigned int c;
	while(ch>> hex>>c){
	ciphertext+=c;
	}
	
	int n_message=ciphertext.length();
	
	char cipher_array[n_message];
	
	

		vector <string> cipher;
	string blk;
	strcpy(cipher_array,ciphertext.c_str());
	int num_of_msgs=0;
	int j=0;
	while(num_of_msgs<(n_message/(1024))){
	for(int p=j;p<(j+(1024));p++){
		blk.append(1, ciphertext[p]);
	}
	//cout<<blk<<endl<<endl<<endl;
	cipher.insert(cipher.end(),blk);
	blk="";
	j=j+(1024);
	num_of_msgs++;
	}
	unsigned char *plaintext;
	
	   unsigned char *ctext;
    unsigned char *S_array = new unsigned char[sha256_desc.hashsize];
    unsigned char *Agg_mac = new unsigned char[sha256_desc.hashsize];
   // unsigned char *temp = new unsigned char[sha256_desc.hashsize];
	unsigned char *k1 = (unsigned char *)key1.c_str();
	for(int i=0;i<100;i++){
	 string m_s = cipher[i];
      
        unsigned char *ctext = (unsigned char *)m_s.c_str();
	
	HMAC_Computation( (char *)ctext, S_array, k1);
            
            string hmac;
            stringstream ss;
            for (int l=0; l<int(sha256_desc.hashsize); l++)
            {
                ss<<hex<<(int)S_array[l];
                hmac= ss.str();
            }
            

        if ( i == 0 ){
          
            strcpy((char *)Agg_mac,(char *)S_array);
        }
        else{
            
            string temp;
            temp = string((const char*)Agg_mac);
            for(int j=0;j<sha256_desc.hashsize;j++)
                temp += S_array[j];
            Agg_mac=hashSHA2((unsigned char*)temp.c_str());
           
            
        }
        

       
        memcpy(k1,hashSHA2(k1),sha256_desc.hashsize);
	
	
	}

	//Aggregate hmac Hex into file
    string Agg_mac_hex;
            stringstream s1;
            for (int l=0; l<int(sha256_desc.hashsize); l++)
            {
                s1<<hex<<(int)Agg_mac[l];
                Agg_mac_hex= s1.str();
            }
         
            cout<<Agg_mac_hex<<endl;
            
         if(Agg_mac_hex==aliceAggregate){
         cout<<"THe aggregated HMAC matches with the received one"<<endl;
         
          ofstream fout2;
	string fname_cipher="matchedAggregateHMAC.txt";
	fout2.open(fname_cipher, ios::out);
	fout2<<Agg_mac_hex;
	fout2.close(); 
         
         ofstream fout;
         string fname_recovedPlainText="Plaintexts.txt";
	fout.open(fname_recovedPlainText, ios::out);

	unsigned char *k = (unsigned char *)key.c_str();
	for(int i=0;i<100;i++){
		
		        string m_s = cipher[i];
      
        unsigned char *m = (unsigned char *)m_s.c_str();
		plaintext=AESctr_decrypt(m,k);
	fout<<plaintext;
	
	memcpy(k,hashSHA2(k),sha256_desc.hashsize);
	
	}
	fout.close();
	}
	else{
	cout<<"Error!!!Authentication Process Failed"<<endl;
	}

	return 0;
}
