// CapPack2.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "pcap.h"
#include "inc.h"
#include "windows.h"
#include <stdio.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32")

void Analyse_IPPacket(const u_char *data);
void Analyse_TCPPacket(const u_char *data);
void packet_handler(u_char* packets,const struct pcap_pkthdr * header,const u_char *pp);

#ifdef DEBUG
HANDLE hLogFile = NULL;
#endif

void main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* ��ȡ�豸�б� */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* �����б� */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;
	}
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	if(inum < 1 || inum > i)
	{
		printf("\n ��������.\n");
		pcap_freealldevs(alldevs);
		return;
	}
	/* ת��ѡ����豸 */
	for(d=alldevs, i=0; i< inum-1; d=d->next, i++)
		;
	/* ���豸 */
	if ( (adhandle= pcap_open_live(d->name, //�豸��
								   65536, // ��׽���������ݰ�
								   1 , // ����ģʽ
								   1, // ���볬ʱ
								   errbuf // ���󻺳�
								  ) ) == NULL)
	{
		printf("Unable to open the adapter");
		pcap_freealldevs(alldevs);
		return;
	}
	printf("\nlistening on %s...\n", d->description);
	/* �����Ѿ�����Ҫ�豸�б���, �ͷ��� */
	pcap_freealldevs(alldevs);

#ifdef DEBUG
	hLogFile=CreateFile("capture.log",GENERIC_WRITE,
						FILE_SHARE_READ|FILE_SHARE_WRITE,
						NULL,
						CREATE_ALWAYS,
						0,
						NULL
					   );
	if (hLogFile == INVALID_HANDLE_VALUE)
	{
		printf("[Error]: Create Log File.\n");
		hLogFile = NULL;
	}
#endif

	pcap_loop(adhandle, 0, packet_handler, NULL);

#ifdef DEBUG
	if(NULL != hLogFile)
		CloseHandle(hLogFile);
#endif

	return;
}

void packet_handler(u_char* packets,const struct pcap_pkthdr *header,const u_char *data)
{
	struct ether_header *eth; //��̫��֡��ͷָ��
	unsigned int ptype; //Э�����ͱ���

	eth=(struct ether_header *)data;
	ptype=ntohs(eth->ether_type);
	switch(ptype)
	{
	case ETHERTYPE_IP:
		Analyse_IPPacket(data+14);
		break;
	default:
#ifdef DEBUG
		printf("unused package:0x%0X\n",ptype);
#endif
		break;
	}

}
//---------------------------------------------------------------------
void Analyse_IPPacket(const u_char *data)
{
	struct iphead *IPHead;

	IPHead=(iphead *)data;
	switch(IPHead->ip_protocol)
	{
	case 6:
		Analyse_TCPPacket(data+20);
		break;
	default:
		break;
	}
	return;
}

char *strfind(char *str, char *tgt)
{
	int tlen = strlen(tgt);
	int max = strlen(str) - tlen;
	register int i;

	for (i = 0; i < max; i++)
	{
		if (memcmp(&str[i], tgt, tlen) == 0)
			return &str[i+tlen];
	}
	return 0;
}

void Analyse_TCPPacket(const u_char *data)
{
	DWORD dwTime = GetTickCount();
	struct tcphead *TCPHead;
	TCPHead=(tcphead *)data;
	const u_char _result_string[] = {0x02,0x00,0x07,0x5f,0x72,0x65,0x73,0x75,0x6c,0x74};
	u_char buffer[256] = {0};

	char command[2048] = {0};

	const u_char *RTMPHeader = NULL;
	const u_char *RTMPBody = NULL;
	const u_char * rtmp_address = NULL;

	if(ntohs(TCPHead->th_sport) == 1935)
	{
		RTMPHeader = data+20;
		if(*RTMPHeader == 0x03 || *(RTMPHeader+7) == 0x14)
		{
			RTMPBody = RTMPHeader+12;
			memcpy(buffer, RTMPBody,170);
			buffer[170] =0;
			if(memcmp(buffer, _result_string, sizeof(_result_string)) == 0)
			{
				rtmp_address = buffer+23;
				if(NULL != strfind((char *)rtmp_address,"rtmp://")
						&& NULL != strfind((char *)rtmp_address,"?"))
				{
					dwTime = GetTickCount();
					sprintf(command,"rtmpdump.exe -r \"%s\" -v -o %d.flvm\n",rtmp_address,dwTime);
					printf("%s\n",command);
					WinExec(command,SW_HIDE);
#ifdef DEBUG
					if(NULL != hLogFile)
					{
						BOOL bErrorFlag = WriteFile(
											  hLogFile,           // open file handle
											  command,      // start of data to write
											  strlen(command),  // number of bytes to write
											  NULL, // number of bytes that were written
											  NULL);            // no overlapped structure

						if (FALSE == bErrorFlag)
						{
							printf("[ERROR]: Unable to write log file.\n");
						}

					}
#endif
				}
			}
		}
	}
}
