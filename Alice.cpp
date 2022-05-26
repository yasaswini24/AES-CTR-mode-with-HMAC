//Alice Code
#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include <iterator>
#include<fstream>
#include<tomcrypt.h>
#include<iomanip>
#include<streambuf>
#include<vector>
#include <sys/stat.h>
using namespace std;

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


unsigned char* AESctr_encrypt(unsigned char *buffer, unsigned char *key)
{
    unsigned char IV[32] = "abcdefghijklmnopqrstuvwxyzabcde";
	symmetric_CTR ctr;
    //int x;
    /* register AES first */
   register_cipher(&aes_desc);
   ctr_start(
             find_cipher("aes"),    /* index of desired cipher */
             IV,                        /* the initial vector */
             key,                       /* the secret key */
             32,                        /* length of secret key (16 bytes) */
             0,                         /* 0 == default # of rounds */
             CTR_COUNTER_LITTLE_ENDIAN, /* Little endian counter */
             &ctr);                    /* where to store the CTR state */

	 ctr_encrypt(buffer,         /* plaintext */
                buffer,         /* ciphertext */
                1024, /* length of plaintext pt */
                &ctr);          /* CTR state */
	ctr_done(&ctr);
    //zeromem(key, sizeof(key));
    zeromem(&ctr, sizeof(ctr));
    return buffer;
}


//--------------------------------------------------------------------------------------------


int main ()
{
//Read Key from InitialKey.txt" 
	string key;
    	fstream filename;
    	filename.open("InitialKey.txt",ios::in);
    	if(filename.is_open()){
    	string x;
    	while(getline(filename,x)){
    	key+=x;
    	}
    	filename.close();
    	}
    	
// Read messages from the file
	ifstream msg_file("Messages.txt");
    	string message((istreambuf_iterator<char>(msg_file)),istreambuf_iterator<char>());
	int n_message=message.length();	
	char message_array[n_message];
	
//split the messages 
	vector <string> mes;
	string blk;
	strcpy(message_array,message.c_str());
	int num_of_msgs=0;
	int j=0;
	while(num_of_msgs<(n_message/1024)){
	for(int p=j;p<(j+1024);p++){
		blk.append(1, message_array[p]);
	}
	mes.insert(mes.end(),blk);
	blk="";
	j=j+1024;
	num_of_msgs++;
	
	}
	//cout<<"/////95///"<<mes[95]<<endl;
	
    //string Ci;
    unsigned char *k = (unsigned char *)key.c_str();
    unsigned char *ciphertext;
    unsigned char *S_array = new unsigned char[sha256_desc.hashsize];
    //unsigned char *S1 = new unsigned char[sha256_desc.hashsize];
    unsigned char *Agg_mac = new unsigned char[sha256_desc.hashsize];
    //unsigned char *temp = new unsigned char[sha256_desc.hashsize];
    string cipher_hex="";
    string cipher="";
    
    
    
    //Save cipher hex in file
    ofstream fout;
    string filenameHMAC="HMACs.txt";
    fout.open(filenameHMAC, ios::out);
   if(n_message%1024==0){
    for (size_t i = 0; i < (n_message/1024); i++){
        
        string m_s = mes[i];
        //cout<<m_s.length();
        unsigned char *m = (unsigned char *)m_s.c_str();
        
        ciphertext = AESctr_encrypt(m,k);
        //cout<<i<<".................."<<ciphertext<<endl;

	//cout<<"-------"<<i<<"-------------"<<ciphertext<<"*************************"<<endl;
     
        
        // Creating Cipher in hex
        for(int i=0;i<1024;i++){
            stringstream cipher_tmp;
            cipher_tmp<<hex<< setw(2) << setfill('0') <<(int)ciphertext[i];
            cipher+= cipher_tmp.str();
            
            cipher_hex += cipher_tmp.str()+" ";
            //cout<<"==="<<cipher_hex.length()<<endl;
            
        }
        //cout<<cipher_hex.length()<<endl;
 
            HMAC_Computation( (char *)ciphertext, S_array, k);
            
            string hmac;
            stringstream ss;
            for (int l=0; l<int(sha256_desc.hashsize); l++)
            {
                ss<<hex<<(int)S_array[l];
                hmac= ss.str();
            }
            fout<<hmac;

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
        
        
        
       
        memcpy(k,hashSHA2(k),sha256_desc.hashsize);
        //cout<<k<<endl;
        //cout<<"key:"<<string((char*)k).length()<<endl;
        
        
        
    }
    fout.close();
    
   
//Aggregate hmac Hex into file
    string Agg_mac_hex;
            stringstream ss;
            for (int k=0; k<int(sha256_desc.hashsize); k++)
            {
                ss<<hex<<(int)Agg_mac[k];
                Agg_mac_hex= ss.str();
            }
            
              ofstream fout1;
	string fname_agghmac="AggregatedHMAC.txt";
	fout1.open(fname_agghmac, ios::out);
	fout1<<Agg_mac_hex;
	fout1.close();
            
           ofstream fout2;
	string fname_cipher="TheCiphertexts.txt";
	fout2.open(fname_cipher, ios::out);
	fout2<<cipher;
	fout2.close(); 
         
       
            
     //cout<<"Aggregate MAC: "<<Agg_mac_hex<<endl;
     //cout<<"Ciper complete: "<<cipher_hex<<endl;
    	// ------ ZeroMQ ------

	// Prepare our context and socket
	zmq::context_t context (1);
	zmq::socket_t socket (context, zmq::socket_type::req);
	cout << "Connecting to server..." << std::endl;
	socket.connect ("tcp://localhost:5555");

	// Send the request
	zmq::message_t request (cipher_hex.size());
	memcpy (request.data(), cipher_hex.data(), cipher_hex.size());
	cout << "Sending Message ..." << std::endl;
	socket.send(request, ZMQ_SNDMORE);
	
	zmq::message_t request2(Agg_mac_hex.size());
	memcpy(request2.data(), Agg_mac_hex.data(), Agg_mac_hex.size());
	socket.send(request2, zmq::send_flags::none);
	}
	else{
	cout<<"The size of the input file must be a multiple of 1024"<<endl;
	//cout<<endl<<"hi3"<<endl;*/
	}return 0;
    
    
  }
    	
    	
    	
