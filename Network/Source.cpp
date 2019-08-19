#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include "Header.h"

int pkcounter = 0;

int main(int argc, char *argv[]) {
	pcap_t *handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	char packet_filter[] = "ip and tcp";

	handle = pcap_open_offline("new.pcap", error_buffer);
	if (handle == NULL){
		printf(error_buffer);
		return 0;
	}
	//loops through pcap file one time
	//each Data packet passes through the fucntion 'my_packet_handler'
	printf("Uploading file...\n");
	pcap_loop(handle, 0, my_packet_handler, NULL);
	pcap_close(handle);

	printf("\n Complete Packet Count: %d\n", count);
	// filter for the probe IP array
	int s = 0;
	for (int y = 0; y < arraySize; y++){
		if (packets[y] > 5 && type[y] != 5){
			tsuspectip[s] = suspectip[y];
			tdestip[s] = destip[y];
			tdestport[s] = destport[y];
			tpackets[s] = packets[y];
			tpkstart[s] = pkstart[y];
			tpkend[s] = pkend[y];
			ttype[s] = type[y];
			if (type[y] == 0){
				strcpy(ptype[s], "Horizontal");
			}
			if (type[y] == 1){
				strcpy(ptype[s], "Vertical");
			}
			if (type[y] == 2){
				strcpy(ptype[s], "Strobe   ");
			}
			s++;
		}
	}
	suspectip = tsuspectip;
	destip = tdestip;
	destport = tdestport;
	packets = tpackets;
	pkstart = tpkstart;
	pkend = tpkend;
	type = ttype;
	arraySize = s;
	
	

	//loop for the UI
	int exit = 0;
	while (exit == 0){
		printf("\n____________________________________________________________________________________________________________\n\n");
		printf("The System has detected %d probes\n", arraySize);
		printf("<1 = List all probe info> \t <2 = Query by IP address> \t <3 = Query by Probe type> \t <4 = Exit>\n");
		int a = 0;
		scanf("%d", &a);
		printf("\nYou entered: %d\n", a);
		if (a == 1){
			print_all();
		}
		if (a == 2){
			ip_query();
		}
		if (a == 3){
			probe_query();
		}
		if (a == 4){
			break;
		}

	}

	free(suspectip);
	free(destip);
	free(destport);
	free(packets);
	free(pkstart);
	free(pkend);
	free(type);
	return 0;
}



//packet handler 
// get packet info and sorts it accordingly 
void my_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct tm ltime;
	char timestr[16];
	ip_header *ih;
	tcp_header *th;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	count++;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* print timestamp and length of the packet */
	//printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	/* retireve the position of the ip header */
	ih = (ip_header *)(pkt_data +
		14); //length of ethernet header

	/* retireve the position of the tcp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	th = (tcp_header *)((u_char *)ih + ip_len);

	// convert from network byte order to host byte order 
	sport = ntohs(th->sport);
	dport = ntohs(th->dport);

	ip_address current = ih->saddr;

	// checks if the aray had duplicates in it_______________________________________
	int ipcount = 0;
	if (count > 16){
		for (int i = 0; i < 15; i++){
			if (sipArray[i] == current){
				
				ipcount++;
				if (ipcount > 3){
					break;
				}
			}
		}
	}

	sipArray[arrayVal] = ih->saddr;

	//enters values into suspectipip array
	if (ipcount > 3)
	{
		//expands arrays if they get to big
		if (arraySize >= 9999){
			max = max + 10000;
			//( *)realloc(, max * sizeof());
			suspectip = (ip_address *)realloc(suspectip, max * sizeof(ip_address));
			destip = (ip_address *)realloc(destip, max * sizeof(ip_address));
			destport = (u_short*)realloc(destport, max * sizeof(u_short));
			packets = (int*)realloc(packets, max * sizeof(int));
			type = (int*)realloc(type, max * sizeof(int));
			pkstart = (timeval*)realloc(pkstart, max * sizeof(timeval));
			pkend = (timeval*)realloc(pkend, max * sizeof(timeval));
		}

		//if array is empty it initializes its first value
		if (arraySize == 0){
			suspectip[arraySize] = ih->saddr;
			destip[arraySize] = ih->daddr;
			destport[arraySize] = dport;
			packets[arraySize] = 1;
			pkstart[arraySize] = header->ts;
			pkend[arraySize] = header->ts;
			type[arraySize] = 5;
			arraySize++;
		}
		//if not then it checks the array to see if the suspect source ip has been added before
		else {
			int temp = 0;
			for (int j = 0; j < arraySize; j++){
				if (suspectip[j] == ih->saddr){
					packets[j]++;
					pkend[j] = header->ts;
					
					if (!(destip[j] == ih->daddr) && type[j] != 2)
					{
						type[j] = 0;
					}
					if (!(destport[j] == dport) && type[j] != 2)
					{
						type[j] = 1;
					}
					if (!(destport[j] == dport) && !(destip[j] == ih->daddr))
					{
						type[j] = 2;
					}
					temp = 1;
				}
			}
			if (temp == 0){
				suspectip[arraySize] = ih->saddr;
				destip[arraySize] = ih->daddr;
				destport[arraySize] = dport;
				packets[arraySize] = 1;
				pkstart[arraySize] = header->ts;
				pkend[arraySize] = header->ts;
				type[arraySize] = 5;
				arraySize++;
			}
		}
	}


	if (count == pkcounter + 1000000){

		printf("Packets Processed: %d...\n", count);
		printf("Suspect Ips: %d...\n\n", arraySize);

		int s = 0;
		for (int y = 0; y < arraySize; y++){
			if (packets[y] > 5 && type[y] != 5){
				tsuspectip[s] = suspectip[y];
				tdestip[s] = destip[y];
				tdestport[s] = destport[y];
				tpackets[s] = packets[y];
				tpkstart[s] = pkstart[y];
				tpkend[s] = pkend[y];
				ttype[s] = type[y];
				s++;
			}
		}
		suspectip= tsuspectip;
		destip = tdestip;
		destport = tdestport;
		packets = tpackets;
		pkstart = tpkstart;
		pkend = tpkend;
		type = ttype;
		arraySize = s;
		
		pkcounter = pkcounter + 1000000;
	}
	

	arrayVal++;
	if (arrayVal == 15){
		arrayVal = 0;
	}
		
	
}

//prints all items in the  array
void print_all(){
	for (int k = 0; k < arraySize; k++){
		printer(k);
	}

}


//asks for an ip and finds it in the array if its there
void ip_query(){

	int exit = 0;
	while (exit == 0){
		printf("\n____________________________________________________________________________________________________________\n\n");
		printf("\nEnter Desired IP address in four seperate parts pressing enter after each \n(EX:part1.part2.part3.part4 ---> part1 *Enter part2 *Enter part3 *Enter part4 *Enter)\n");

		ip_address temp; 
		int num = 0;
		scanf("%d", &temp.byte1);
		if (temp.byte1 == 1){
			break;
		}
		scanf("%d", &temp.byte2);
		if (temp.byte2 == 1){
			break;
		}
		scanf("%d", &temp.byte3);
		if (temp.byte3 == 1){
			break;
		}
		scanf("%d", &temp.byte4);
		if (temp.byte4 == 1){
			break;
		}

		printf("\nYou Entered:  %d.%d.%d.%d\n\n",
			temp.byte1,
			temp.byte2,
			temp.byte3,
			temp.byte4);

		for (int k = 0; k < arraySize; k++){
			
			if (temp == suspectip[k]){
			num++;
			 
			printer(k);
			}
		}

		if (num == 0){
			printf("\nIP adress not found\n");
		}


		printf("\n____________________________________________________________________________________________________________\n\n");
		printf("\n< 1 = Query another IP adress > < 2 = Go back >\n");
		int a = 0;
		scanf("%d", &a);

		if (a == 2){
			break;
		}
		else if (a == 1){}
		else{
			printf("ERROR: Wrong Command");
			break;
		}

	}


}



//asks for a prob type to filter the array by
void probe_query(){

	int exit = 0;
	while (exit == 0){
		printf("\n____________________________________________________________________________________________________________\n\n");
		printf("\n<1 = List all Horizontal> \t <2 = List all Vertical> \t <3 = List all strobe> \t <4 = Exit>\n");
		char t[14];
		int a = 0;
		scanf("%d", &a);
		

		if (a>0 && a<4){

			for (int k = 0; k < arraySize; k++){

				if ((a-1) == type[k])
				{
					printer(k);
				}
			}

		}
		else{
			break;
		}
	}

}





int sub_string(char *a){
	int re = 0;
	char holda[3];
	int ina;

	//hours
	memcpy(&holda, &a[0], 2);
	holda[2] = '\0';


	ina = atol(holda);
	re = re + (ina * 60 * 60);
	

	//mins
	memcpy(&holda, &a[3], 2);
	holda[2] = '\0';

	ina = atol(holda);

	re = re + (ina) * 60;
	
	//sec
	memcpy(&holda, &a[6], 2);
	holda[2] = '\0';

	ina = atol(holda);

	re = re + (ina);

	return re;

}

void printer(int k){
	struct tm ltime;
	struct tm ltime1;
	time_t local_tv_sec;
	time_t local_tv_sec1;
	char start[20];
	char end[20];
	local_tv_sec = pkstart[k].tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(start, sizeof start, "%H:%M:%S", &ltime);
	local_tv_sec1 = pkend[k].tv_sec;
	localtime_s(&ltime1, &local_tv_sec1);
	strftime(end, sizeof end, "%H:%M:%S", &ltime1);

	//printf("Source IP: %d.%d.%d.%d    \t pribe type: %d    \t start: %s \t end: %s \t rate: %d\n",


	float s = (pkstart[k].tv_usec);
	s = s *.000001;
	float e = pkend[k].tv_usec;
	e = e *.000001;
	int tstart = sub_string(start);
	int tend = sub_string(end);

	s = s + tstart;
	e = e + tend;

	float temp = (e - s);
	if (temp <= -1){
		temp = 86400 + temp;
	}

	printf("Src IP: %d.%d.%d.%d\t Probe type: %s    \t start: %s \t end: %s \t Pakets per second: %.6f\n",
		suspectip[k].byte1,
		suspectip[k].byte2,
		suspectip[k].byte3,
		suspectip[k].byte4,
		ptype[k],
		start,
		end,
		packets[k] / temp);


}