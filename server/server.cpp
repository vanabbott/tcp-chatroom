/*
  Name: Dominic Marques
  Flahavan Abbott
*/
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "pg3lib.h"
#include <ctime>
#include <iostream>
#include <fstream>
#include <pthread.h>
#include <map>
#include <iostream>
#include <vector>
using namespace std;

/* Credentials format:
username, password
username, password
*/
#define MAX_PENDING 10
#define CREDENTIALS_FILE "credentials.txt"
#define MAX_LINE 4096

pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cred_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t user_mutex = PTHREAD_MUTEX_INITIALIZER;
map < string, string > credentials;
map < string, int > users;
map < string, string > user_keys;
int s;
char * pubKey = getPubKey();
struct client_info {
    struct sockaddr client_addr;
    unsigned addr_len;
    string username;
    char * key;
    pthread_t thread_id;
    int sockfd;
};

void add_credentials(string username, string password) {
    pthread_mutex_lock( & cred_mutex);
    credentials[username] = password;
    pthread_mutex_unlock( & cred_mutex);
    fstream fs;
    pthread_mutex_lock( & file_mutex);
    fs.open(CREDENTIALS_FILE);
    string complete = username + "," + password + "\n";
    cout << complete << endl;
    char buf[4096];
    strcpy(buf, complete.c_str());
    fs.seekg(0, fs.end);
    fs.write(buf, strlen(buf));
    pthread_mutex_unlock( & file_mutex);
}

bool handle_login(client_info & info) {
    char buf[4096];
    int len;
    pthread_mutex_lock( & cred_mutex);
    bool registered = credentials.count(info.username);
    pthread_mutex_unlock( & cred_mutex);
    if (registered) { // username found
        strcpy(buf, "LOGIN");
        len = sizeof(buf);
        if (send(info.sockfd, buf, MAX_LINE, 0) == -1) {
            fprintf(stderr, "Server send error: %s\n", strerror(errno));
        }
    } else { // username not found
        strcpy(buf, "REGISTER");
        len = sizeof(buf);
        if (send(info.sockfd, buf, MAX_LINE, 0) == -1) {
            fprintf(stderr, "Server send error: %s\n", strerror(errno));
        }
    }
    string password;
    bool correct;
    do {
        bzero((char * ) & buf, sizeof(buf));
        // receive password
        if (recv(info.sockfd, buf, MAX_LINE, 0) == -1) {
            perror("Receive error!\n");
            pthread_exit(NULL);
        }
        password = decrypt(buf);
        cout << "password: " << password << endl;
        if (!registered) {
            add_credentials(info.username, password);
        }
        pthread_mutex_lock( & cred_mutex);
        correct = (password == credentials[info.username]);
        pthread_mutex_unlock( & cred_mutex);
        if (!correct) {
            cout << "INCORRECT PASSWORD: " << password << endl;
            cout << "Should be: " << credentials[info.username] << endl;
            strcpy(buf, "INCORRECT PASSWORD");
            len = sizeof(buf);
            if (send(info.sockfd, buf, MAX_LINE, 0) == -1) {
                fprintf(stderr, "Server send error: %s\n", strerror(errno));
            }
        }
    } while (!correct);
    // login successful
    strcpy(buf, "VERIFIED");
    len = sizeof(buf);
    if (send(info.sockfd, buf, MAX_LINE, 0) == -1) {
        fprintf(stderr, "Server send error: %s\n", strerror(errno));
    }
    // get public client key
    if (recv(info.sockfd, buf, MAX_LINE, 0) == -1) {
        perror("Receive error!\n");
        pthread_exit(NULL);
    }
    info.key = strdup(buf);
}

void load_credentials() {
    ifstream fs;
    fs.open(CREDENTIALS_FILE);
    int i;
    char buf[4096];
    string cred, username, password;
    if (fs) {
        while (fs.getline(buf, 4096)) {
            cred = buf;
            i = cred.find(',');
            username = cred.substr(0, i);
            password = cred.substr(i + 1);
            credentials[username] = password;
        }
    } else {
        cerr << "Unable to open credentials file" << endl;
        exit(1);
    }
    fs.close();
}

void send_confirmation(client_info &info, bool success) {
    cout << "sending confirmation: " << success << endl;
    char buf[4096];
    if (success) {
        strcpy(buf, "SENT");
    } else {
        strcpy(buf, "NOTSENT");
    }
    if (send(info.sockfd, buf, MAX_LINE, 0) == -1) {
        fprintf(stderr, "Server send error: %s\n", strerror(errno));
    }
    cout << "confirmation sent" << endl;
}

void * client_handler(void * c_info) {
    cout << "in thread" << endl;
    client_info info = * (client_info * ) c_info;
    cout << "info done" << endl;
    int len;
    char buf[4096];
    char buf2[4096];
    char buf3[4096];
    bool success = true;
    if ((len = recv(info.sockfd, buf, MAX_LINE, 0)) == -1) {
        perror("Server Received Error!");
        pthread_exit(NULL);
    }
    info.username = buf;
    cout << "username: " << info.username << endl;
    // send public key
    strcpy(buf, pubKey);
    len = strlen(buf);
    if (send(info.sockfd, buf, MAX_LINE, 0) == -1) {
        fprintf(stderr, "Server send error: %s\n", strerror(errno));
    }
    // handle login
    handle_login(info);

    // update list of users
    pthread_mutex_lock( & user_mutex);
    users[info.username] = info.sockfd;
    user_keys[info.username] = info.key;
    pthread_mutex_unlock( & user_mutex);

    //receive command from client
    bzero((char * ) & buf, sizeof(buf));
    if ((len = recv(info.sockfd, buf, MAX_LINE, 0)) == -1) {
        perror("Server Received Error!");
        pthread_exit(NULL);
    }

    //size_t last_word = 0;
    int start;
    int send_sockfd;
    char* send_key;
    while (strncmp(buf, "EX", 2) != 0) {
        success = true;
        if (strncmp(buf, "PM", 2) == 0) {
            // PRIVATE MESSAGE
            // get list of users
            bzero((char * ) & buf, sizeof(buf));
            bzero((char * ) & buf2, sizeof(buf2));
            bzero((char * ) & buf3, sizeof(buf3));
            start = 0;
            for (auto u: users) {
                //cout << u.first << endl;
                if (u.first.compare(info.username) != 0) {
                    strcpy(buf2, buf3);
                    bzero((char * ) & buf3, sizeof(buf3));
                    u.first.copy(buf, sizeof(u.first), 0);
                    if (!start) {
                        start = 1;
                        //cout << "HERE" << endl;
                        sprintf(buf3, "%s", buf);
                    } else {
                        sprintf(buf3, "%s, %s", buf2, buf);
                    }
                    bzero((char * ) & buf, sizeof(buf));
                    bzero((char * ) & buf2, sizeof(buf2));
                }
            }
            // send list of users
            if (send(info.sockfd, buf3, MAX_LINE, 0) == -1) {
                fprintf(stderr, "Server send error: %s\n", strerror(errno));
            }
            bzero((char * ) & buf, sizeof(buf));
            bzero((char * ) & buf2, sizeof(buf2));
            bzero((char * ) & buf3, sizeof(buf3));

            // recieve name of recipient
            if ((len = recv(info.sockfd, buf, MAX_LINE, 0)) == -1) {
                perror("Server Received Error!");
                pthread_exit(NULL);
            }
            cout << "getting user" << endl;
            for (auto u: users) {
                if (u.first.compare(buf) == 0) {
                    send_sockfd = u.second;
                    send_key = strdup(user_keys[u.first].c_str());
                }
            }
            cout << "user got" << endl;
            // receive message to send
            bzero((char * ) & buf, sizeof(buf));
            if ((len = recv(info.sockfd, buf, MAX_LINE, 0)) == -1) {
                perror("Server Received Error!");
                pthread_exit(NULL);
            }
            cout << "Encrypted: " << buf << endl;
            strcpy(buf3, decrypt(buf));
            cout << "Decrypted: " << buf3 << endl;
            bzero((char * ) & buf, sizeof(buf));
            strcpy(buf, encrypt(buf3, send_key));
            cout << "Encrypted: " << buf << endl;
            sprintf(buf2, "P%s", buf);
            if (send(send_sockfd, buf2, MAX_LINE, 0) == -1) {
                success = false;
                fprintf(stderr, "Server send error: %s\n", strerror(errno));
            }
            bzero((char * ) & buf, sizeof(buf));
            bzero((char * ) & buf2, sizeof(buf2));
            send_confirmation(info, success);

        } else if (strncmp(buf, "BM", 2) == 0) {
            // BROADCAST MESSAGE
            // receive message to broadcast
            bzero((char * ) & buf, sizeof(buf));
            bzero((char * ) & buf2, sizeof(buf2));
            if ((len = recv(info.sockfd, buf, MAX_LINE, 0)) == -1) {
                perror("Server Received Error!");
                pthread_exit(NULL);
            }
            sprintf(buf2, "B%s", buf);
            // send message to everyone
            for (auto u: users) {
                if (u.second != info.sockfd) {
                    if (send(u.second, buf2, MAX_LINE, 0) == -1) {
                        success = false;
                        fprintf(stderr, "Server send error: %s\n", strerror(errno));
                    }
                }
            }
            bzero((char * ) & buf2, sizeof(buf2));
            bzero((char * ) & buf, sizeof(buf));
            send_confirmation(info, success);
            // send confirmation
            /*sprintf(buf, "SENT");
            if(send(info.sockfd, buf, MAX_LINE, 0) == -1){
            		fprintf(stderr, "Server send error: %s\n", strerror(errno));
            }
            bzero((char*)&buf, sizeof(buf));*/

        }
        bzero((char * ) & buf, sizeof(buf));
        if ((len = recv(info.sockfd, buf, MAX_LINE, 0)) == -1) {
            perror("Server Received Error!");
            pthread_exit(NULL);
        }
    }
    // EXIT
    strncpy(buf, "X", 2);
    if (send(info.sockfd, buf, MAX_LINE, 0) == -1) {
        fprintf(stderr, "Server send error: %s\n", strerror(errno));
    }
    // update list of users
    pthread_mutex_lock( & user_mutex);
    users.erase(info.username);
    user_keys.erase(info.username);
    pthread_mutex_unlock( & user_mutex);

    pthread_exit(NULL);
}

int main(int argc, char
    const * argv[]) {
    if (argc < 2) {
        printf("Invalid input\n");
        exit(1);
    }
    int len, recieved;
    struct sockaddr_in sin, client_addr;
    unsigned addr_len = sizeof(client_addr);
    const void * opt;
    char buf[4096];
    unsigned long check;
    char * decrypted, * encrypted;
    time_t timestamp = time(nullptr);

    bzero((char * ) & sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(atoi(argv[1]));
    /* setup passive open */
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("simplex-talk: socket");
        exit(1);
    }
    // set socket option
    if ((setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char * ) & opt, sizeof(int))) < 0) {
        perror("simplex-talk:setscokt");
        exit(1);
    }
    if ((bind(s, (struct sockaddr * ) & sin, sizeof(sin))) < 0) {
        perror("simplex-talk: bind");
        exit(1);
    }
    if ((listen(s, MAX_PENDING)) < 0) {
        perror("simplex-talk: listen");
        exit(1);
    }
    load_credentials();
    pthread_t thread_id;
    while (1) {
        client_info info;
        info.addr_len = sizeof(info.client_addr);
        if ((recieved = accept(s, (struct sockaddr * ) & info.client_addr, & info.addr_len)) != -1) {
            puts("Connection accepted");
            info.sockfd = recieved;
            if (pthread_create( & thread_id, NULL, client_handler, (void * ) & info) < 0) {
                perror("could not create thread");
                return 1;
            }
            //Now join the thread , so that we dont terminate before the thread
            //pthread_join( thread_id , NULL);
            puts("Handler assigned");
        }
    }

    close(s);
    return 0;
}
