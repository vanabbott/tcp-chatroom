/*
  Name: Dominic Marques
  Flahavan Abbott
*/
#include <string>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdlib>
#include "pg3lib.h"
#include <chrono>
#include <iostream>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <pthread.h>
using namespace std;

#define MAX_LINE 4096
pthread_mutex_t msg_mutex = PTHREAD_MUTEX_INITIALIZER;
char message[MAX_LINE];
int message_received;
char * serverKey;

void * message_handler(void * sockfd) {
    int s = * (int * ) sockfd;
    char buf[MAX_LINE];
    int len;
    while (strncmp(buf, "X", 1) != 0) {
        bzero((char * ) & buf, sizeof(buf));
        if ((len = recv(s, buf, MAX_LINE, 0)) == -1) {
            perror("Client Received Error");
            pthread_exit(NULL);
        }
        if (strncmp(buf, "P", 1) == 0 || strncmp(buf, "B", 1) == 0) { // Client received DATA MESSAGE
            if (strncmp(buf, "P", 1) == 0) {
                strcpy(buf, decrypt((char * )(buf + 1)));
                cout << endl << "*****INCOMING MESSAGE*****  " << endl << (char * )(buf) << endl;
            } else {
                cout << endl << "*****INCOMING MESSAGE*****  " << endl << (char * )(buf + 1) << endl;
            }
        }  else if (strncmp(buf, "SENT", 4) == 0) {
			cout << "Message sent" << endl;
		} else if (strncmp(buf, "NOTSENT", 7) == 0) {
			cout << "Message failed to send" << endl;
		} else if (strncmp(buf, "X", 1) != 0) { // Client received command message
            pthread_mutex_lock( & msg_mutex);
            bzero((char * ) & message, sizeof(message));
            //cout << "BUF: " << buf << endl;
            strcpy(message, buf);
            //cout << message << endl;
            message_received = 1;
            pthread_mutex_unlock( & msg_mutex);
        }
        cout << "> " << flush;
    }
    pthread_exit(NULL);

}

void handle_user_input(string * input, int s) {
    string pm = ("PM");
    string bm = ("BM");
    char buf[MAX_LINE];
    string send_name;
    //char *token;
    //const char delim[2] = ":";
    if (input -> compare(pm) == 0) {
        // PRIVATE MESSAGE

        // receive response of names
        cout << "Peers Online:" << endl;
        while (!message_received) {}
        cout << message << endl;

        // ask for and send name of peer to message
        cout << "Peer to Message:" << endl;
        bzero((char * ) & buf, sizeof(buf));
        getline(cin, send_name);
        send_name.copy(buf, send_name.length());
        if (send(s, buf, MAX_LINE, 0) == -1) {
            fprintf(stderr, "Client send error: %s\n", strerror(errno));
        }

        // ask for and send message to peer
        cout << "Message to Send Privately: \n";
        bzero((char * ) & buf, sizeof(buf));

        getline(cin, * input);
        bzero((char * ) & buf, sizeof(buf));
        input -> copy(buf, input -> length());
        strcpy(buf, encrypt(buf, serverKey));
        if (send(s, buf, MAX_LINE, 0) == -1) {
            fprintf(stderr, "Client send error: %s\n", strerror(errno));
        }
    } else if (input -> compare(bm) == 0) {
        // BROADCAST MESSAGE
        cout << "Message to Broadcast Publicly: \n";
        bzero((char * ) & buf, sizeof(buf));
        getline(cin, * input);
        bzero((char * ) & buf, sizeof(buf));
        input -> copy(buf, input -> length());
        if (send(s, buf, MAX_LINE, 0) == -1) {
            fprintf(stderr, "Client send error: %s\n", strerror(errno));
        }
        //cout << "INSIDE HANDLE INPUT: " << message << endl;
    }

    return;
}

int main(int argc, char
    const * argv[]) {
    if (argc < 4) {
        printf("Invalid input\n");
        exit(1);
    }
    std::ifstream fs;
    struct hostent * hp;
    struct sockaddr_in sin;
    unsigned addr_len = 0;
    char buf[MAX_LINE];
    int s, len;
    char * pubKey = getPubKey();
    unsigned long check;
    time_t serverTime;
    pthread_t thread_id;

    /* translate host name into peer's IP address */
    hp = gethostbyname(argv[1]);
    if (!hp) {
        fprintf(stderr, "unknown host: %s\n", argv[1]); // TODO: change string
        exit(1);
    }

    bzero((char * ) & sin, sizeof(sin));
    sin.sin_family = AF_INET;
    bcopy(hp -> h_addr, (char * ) & sin.sin_addr, hp -> h_length);
    sin.sin_port = htons(atoi(argv[2]));
    /* active open */
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("simplex-talk: socket");
        exit(1);
    }
    if (connect(s, (struct sockaddr * ) & sin, sizeof(sin)) < 0) {
        perror("simplex-talk: connect");
        close(s);
        exit(1);
    }

    // send username
    strcpy(buf, argv[3]);
    len = sizeof(argv[3]);
    if (send(s, buf, MAX_LINE, 0) == -1) {
        fprintf(stderr, "Client send error: %s\n", strerror(errno));
    }
    // get serverKey
    bzero((char * ) & buf, sizeof(buf));
    if ((recv(s, buf, MAX_LINE, 0)) == -1) {
        perror("Receive error!\n");
        exit(1);
    }
    serverKey = strdup(buf);
    bzero((char * ) & buf, sizeof(buf));
    // is valid user?
    bzero((char * ) & buf, sizeof(buf));
    if ((recv(s, buf, MAX_LINE, 0)) == -1) {
        perror("Receive error!\n");
        exit(1);
    }
    if (strncmp(buf, "REGISTER", 8) == 0) {
        cout << "Creating new user" << endl;
    } else {
        cout << "Existing user" << endl;
    }

    // password
    do {
        bzero((char * ) & buf, sizeof(buf));
        cout << "Enter password: ";
        cin >> buf;
        strcpy(buf, encrypt(buf, serverKey));
        len = sizeof(buf);
        if (send(s, buf, MAX_LINE, 0) == -1) {
            fprintf(stderr, "Client send error: %s\n", strerror(errno));
        }

        bzero((char * ) & buf, sizeof(buf));
        if ((recv(s, buf, MAX_LINE, 0)) == -1) {
            perror("Receive error!\n");
            exit(1);
        }
        cout << buf << endl;
        if (strncmp(buf, "VERIFIED", 8) == 0) {
            cout << "Login successful" << endl;
        } else {
            cout << "Login unsucessful" << endl;
        }
    } while (strncmp(buf, "VERIFIED", 8) != 0);
    // send public key
    strcpy(buf, pubKey);
    len = sizeof(buf);
    if (send(s, buf, MAX_LINE, 0) == -1) {
        fprintf(stderr, "Client send error: %s\n", strerror(errno));
    }
    string cmd;

    // create listening thread
    if (pthread_create( & thread_id, NULL, message_handler, (void * ) & s) < 0) {
        perror("could not create thread");
        return 1;
    }

    // take input for commands
    while (cmd != "EX") {
        bzero((char * ) & buf, sizeof(buf));
        cout << "Input Command (BM: Broadcast Message, PM: Private Message, EX: Exit)" << endl << "> ";
        getline(cin, cmd);
        cmd.copy(buf, cmd.length());
        if (send(s, buf, MAX_LINE, 0) == -1) {
            fprintf(stderr, "Client send error: %s\n", strerror(errno));
        }
        if (cmd != "EX") {
            message_received = 0;
            handle_user_input( & cmd, s);
        }
    }
    // wait for listening thread to terminate
    pthread_join(thread_id, NULL);
    close(s);
    return 0;
}
