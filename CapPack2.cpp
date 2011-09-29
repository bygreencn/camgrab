// CapPack2.cpp : 定义控制台应用程序的入口点。
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

HANDLE hFile;

void main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* 获取设备列表 */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* 数据列表 */
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
		printf("\n 输入有误.\n");
		pcap_freealldevs(alldevs);
		return;
	}
	/* 转到选择的设备 */
	for(d=alldevs, i=0; i< inum-1; d=d->next, i++)
		;
	/* 打开设备 */
	if ( (adhandle= pcap_open_live(d->name, //设备名
								   65536, // 捕捉完整的数据包
								   1 , // 混在模式
								   1, // 读入超时
								   errbuf // 错误缓冲
								  ) ) == NULL)
	{
		printf("Unable to open the adapter");
		pcap_freealldevs(alldevs);
		return;
	}
	printf("\nlistening on %s...\n", d->description);
	/* 我们已经不需要设备列表了, 释放它 */
	pcap_freealldevs(alldevs);

	//hFile=CreateFile("C:\\aaa.txt",GENERIC_WRITE,0, NULL,CREATE_ALWAYS,0,NULL);

	pcap_loop(adhandle, 0, packet_handler, NULL);


	//CloseHandle(hFile);
	return;
}

void packet_handler(u_char* packets,const struct pcap_pkthdr *header,const u_char *data)
{
	struct ether_header *eth; //以太网帧报头指针
	unsigned int ptype; //协议类型变量

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

	char command[512] = {0};

	const u_char *RTMPHeader = NULL;
	const u_char *RTMPBody = NULL;
	const u_char * rtmp_address = NULL;

	if(ntohs(TCPHead->th_sport) == 1935)
	{
		RTMPHeader = data+20;
		if(*RTMPHeader == 0x03 || *(RTMPHeader+7) == 0x14)
		{
			RTMPBody = RTMPHeader+12;
			memcpy(buffer, RTMPBody,146);
			buffer[146] =0;
			if(memcmp(buffer, _result_string, sizeof(_result_string)) == 0)
			{
				rtmp_address = buffer+23;
				if(NULL != strfind((char *)rtmp_address,"rtmp://")
						&& NULL != strfind((char *)rtmp_address,"?"))
				{
					dwTime = GetTickCount();
					sprintf(command,"rtmpdump.exe -r \"%s\" -v -o %d.flv",rtmp_address,dwTime);
					printf("%s\n",command);
					WinExec(command,SW_HIDE);
				}
			}
		}
	}
}
