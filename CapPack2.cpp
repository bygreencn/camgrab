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
void Analyse_TCPPacket(const u_char *data, int length);
void packet_handler(u_char* packets,const struct pcap_pkthdr * header,const u_char *pp);

HANDLE hFile;

/*
const u_char pattenCAM[] =
{
	0x03,0x00,0x00,0x00,0x00,0x00,0x90,0x14,
	0x00,0x00,0x00,0x00,0x02,0x00,0x07,0x5f,
	0x72,0x65,0x73,0x75,0x6c,0x74,0x00,0x40,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,
	0x02,0x00,0x79
};

const int pattenCAMLength = 35;
*/
const u_char pattenCAM[] =
{
		0x02,0x00,0x07,0x5f,
		0x72,0x65,0x73,0x75,0x6c,0x74,0x00,0x40,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,
		0x02,0x00
};

const int pattenCAMLength = 22;


int prefixPattenCAM[] =
{
	-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,
};

const int default_link_length = 121;

bool prefixGen(u_char *pattern,int patternLen,int *prefixArray);
int kmpFind(u_char *sample, int length, int *prefixArray,u_char *pattern, int patten_length);



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

	if(false == prefixGen((u_char*)pattenCAM,sizeof(pattenCAM),prefixPattenCAM))
	{
		printf("KMP prefix Array generate error!");
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
	{
		int ip_len = IPHead->ip_header_length * 4;
		u_char* tappacket=(u_char*)IPHead + ip_len;   //数据的真正起点
		int tappacketLength=ntohs(IPHead->ip_length) - ip_len;    //应用层数据长度
		Analyse_TCPPacket(tappacket,tappacketLength);
	}
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

void Analyse_TCPPacket(const u_char *data, int length)
{
	DWORD dwTime = GetTickCount();
	struct tcphead *TCPHead;
	TCPHead=(tcphead *)data;
	u_char buffer[256] = {0};
	char command[512] = {0};

	u_char *RTMPHeader = NULL;
	int strlength = 121;


	if(ntohs(TCPHead->th_sport) == 1935)
	{
		RTMPHeader = (u_char*)data+sizeof(tcphead);

		int pos = kmpFind(RTMPHeader,
						  length-sizeof(tcphead),
						  prefixPattenCAM,
						  (u_char*)pattenCAM,
						  pattenCAMLength);
		if(-1 != pos)
		{
			dwTime = GetTickCount();
			strlength = *(RTMPHeader+pos+pattenCAMLength);
			if(pos+pattenCAMLength+strlength+1+sizeof(tcphead) > length)
				return;
			memcpy(buffer,RTMPHeader+pos+pattenCAMLength+1,strlength);
			sprintf(command,"rtmpdump.exe -r \"%s\" -v -o %d.flvm",
				buffer,
				dwTime);
			printf("%s\n",command);
			WinExec(command,SW_HIDE);
		}
	}
}
bool prefixGen(u_char *pattern,int patternLen,int *prefixArray)
{
	int i;
	if(patternLen <= 0)
		return false;
	prefixArray[0] = -1;
	int k = -1;//前一次的匹配前缀的最大索引
	for(i=1; i<patternLen; i++)
	{
		while (k >= 0 && pattern[k+1] != pattern[i])
		{
			k = prefixArray[k];
		}

		if (pattern[k+1] == pattern[i])
		{
			k++;
		}

		prefixArray[i] = k;
	}
}

int kmpFind(u_char *sample, int length, int *prefixArray,u_char *pattern, int patten_length)
{
	int k = -1;//匹配前缀最大索引
	if(length<patten_length+default_link_length)
		return -1;
	for(int i=0; i < length; i++)
	{
		while( k >=0 && pattern[k+1] != sample[i])
		{
			k = prefixArray[k];
		}

		if (pattern[k+1] == sample[i])
		{
			k++;
		}

		if(k == patten_length-1)
		{
			printf("matching at %d offset\n",i-k);
			return i-k;

			//if neet to continue match, the next pos is
			//k = prefixArray[k];

		}
	}
	return -1;
}
